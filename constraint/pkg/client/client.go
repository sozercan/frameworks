// Package client provides the main client for interacting with the constraint framework.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	apiconstraints "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	regoSchema "github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego/schema"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/instrumentation"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/v1/util"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const statusField = "status"

// Client tracks ConstraintTemplates and Constraints for a set of Targets.
// Allows validating reviews against Constraints.
//
// Threadsafe. Does not support concurrent mutation operations.
//
// Note that adding per-identifier locking would not fix this completely - the
// thread for the first-sent call could be put to sleep while the second is
// allowed to continue running. Thus, this problem can only safely be handled
// by the caller.
type Client struct {
	// driver priority specifies the preference for which driver should
	// be preferred if a template specifies multiple kinds of source
	// code. It is determined by the order with which drivers are
	// added to the client.
	driverPriority map[string]int

	// ignoreNoReferentialDriverWarning toggles whether we warn the user
	// when there is no registered driver that supports referential data when
	// they call AddData()
	ignoreNoReferentialDriverWarning bool

	// drivers contains the drivers for policy engines understood
	// by the constraint framework client.
	// Does not require mutex locking as Driver is threadsafe
	// and the map should be created during bootstrapping.
	drivers map[string]drivers.Driver
	// targets are the targets supported by this Client.
	// Assumed to be constant after initialization.
	targets map[string]handler.TargetHandler

	// mtx guards reading and writing data outside of Driver.
	mtx sync.RWMutex

	// templates is a map from a Template's name to its entry.
	templates map[string]*templateClient

	// enforcementPoints is array of enforcement points for which this client may be used.
	enforcementPoints []string
}

// ARGetter is an interface for getting an AdmissionRequest.
type ARGetter interface {
	GetAdmissionRequest() *admissionv1.AdmissionRequest
}

// driverForTarget returns the driver to be used for a target according to the
// driver priority in the client. An empty string means the target does not
// contain a language the client has a driver for.
func (c *Client) driverForTarget(target templates.Target) string {
	language := ""
	for _, v := range target.Code {
		priority, ok := c.driverPriority[v.Engine]
		if !ok {
			continue
		}
		if priority < c.driverPriority[language] || c.driverPriority[language] == 0 {
			language = v.Engine
		}
	}
	return language
}

func (c *Client) targetDriversForTemplate(template *templates.ConstraintTemplate) (map[string]string, error) {
	targetDrivers := make(map[string]string, len(template.Spec.Targets))
	for _, target := range template.Spec.Targets {
		driverName := c.driverForTarget(target)
		if driverName == "" {
			return nil, fmt.Errorf("%w: available drivers: %v, target %q has no supported engine", clienterrors.ErrNoDriver, c.driverPriority, target.Target)
		}
		targetDrivers[target.Target] = driverName
	}
	return targetDrivers, nil
}

func templateForDriver(template *templates.ConstraintTemplate, targetDrivers map[string]string, driverName string) *templates.ConstraintTemplate {
	result := template.DeepCopy()
	result.Spec.Targets = nil
	for _, target := range template.Spec.Targets {
		if targetDrivers[target.Target] == driverName {
			result.Spec.Targets = append(result.Spec.Targets, *target.DeepCopy())
		}
	}
	return result
}

func driverNames(targetDrivers map[string]string) []string {
	set := make(map[string]struct{}, len(targetDrivers))
	for _, driverName := range targetDrivers {
		set[driverName] = struct{}{}
	}
	names := make([]string, 0, len(set))
	for driverName := range set {
		names = append(names, driverName)
	}
	sort.Strings(names)
	return names
}

// CreateCRD creates a CRD from template.
func (c *Client) CreateCRD(ctx context.Context, templ *templates.ConstraintTemplate) (*apiextensions.CustomResourceDefinition, error) {
	if templ == nil {
		return nil, fmt.Errorf("%w: got nil ConstraintTemplate",
			clienterrors.ErrInvalidConstraintTemplate)
	}

	err := validateTemplateMetadata(templ)
	if err != nil {
		return nil, err
	}

	targets, err := c.getTargetHandlers(templ)
	if err != nil {
		return nil, err
	}

	return createCRD(ctx, templ, targets...)
}

// AddTemplate adds the template source code to OPA and registers the CRD with the client for
// schema validation on calls to AddConstraint. On error, the responses return value
// will still be populated so that partial results can be analyzed.
func (c *Client) AddTemplate(ctx context.Context, templ *templates.ConstraintTemplate) (*types.Responses, error) {
	resp := types.NewResponses()

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if templ == nil {
		return resp, fmt.Errorf("%w: got nil ConstraintTemplate", clienterrors.ErrInvalidConstraintTemplate)
	}
	if err := validateTemplateMetadata(templ); err != nil {
		return resp, err
	}
	targets, err := c.getTargetHandlers(templ)
	if err != nil {
		return resp, err
	}
	targetDrivers, err := c.targetDriversForTemplate(templ)
	if err != nil {
		return resp, err
	}
	crd, err := createCRD(ctx, templ, targets...)
	if err != nil {
		return resp, err
	}

	var cachedCpy *templates.ConstraintTemplate
	hasConstraints := false
	var oldTargets []string

	cached := c.templates[templ.GetName()]
	if cached != nil && cached.template != nil {
		cachedCpy = cached.getTemplate()
		hasConstraints = len(cached.constraints) > 0
		for _, target := range cached.targets {
			oldTargets = append(oldTargets, target.GetName())
		}
	}

	desiredDrivers := driverNames(targetDrivers)
	if cachedCpy != nil && cachedCpy.SemanticEqual(templ) && activeDriversMatch(cached, desiredDrivers) {
		for targetName := range targetDrivers {
			resp.Handled[targetName] = true
		}
		return resp, nil
	}

	if hasConstraints {
		var newTargets []string
		for _, target := range templ.Spec.Targets {
			newTargets = append(newTargets, target.Target)
		}

		if len(oldTargets) != len(newTargets) {
			return resp, fmt.Errorf("%w: old targets %v, new targets %v",
				clienterrors.ErrChangeTargets, oldTargets, newTargets)
		}

		sort.Strings(oldTargets)
		sort.Strings(newTargets)

		for i, target := range oldTargets {
			if target != newTargets[i] {
				return resp, fmt.Errorf("%w: old targets %v, new targets %v",
					clienterrors.ErrChangeTargets, oldTargets, newTargets)
			}
		}
	}

	templateName := templ.GetName()
	cacheEntry := c.templates[templateName]
	if cacheEntry == nil {
		cacheEntry = newTemplateClient()
		c.templates[templateName] = cacheEntry
	}

	oldDesiredDrivers := make(map[string]struct{})
	for _, driverName := range cacheEntry.targetDrivers {
		oldDesiredDrivers[driverName] = struct{}{}
	}
	for _, driverName := range desiredDrivers {
		driver, ok := c.drivers[driverName]
		if !ok {
			return resp, fmt.Errorf("%w: available drivers: %v, wanted %q", clienterrors.ErrNoDriver, c.driverPriority, driverName)
		}
		if err := driver.AddTemplate(ctx, templateForDriver(templ, targetDrivers, driverName)); err != nil {
			return resp, err
		}
		cacheEntry.activeDrivers[driverName] = true
		if _, wasDesired := oldDesiredDrivers[driverName]; !wasDesired {
			cacheEntry.needsConstraintReplay[driverName] = true
		}
		if cacheEntry.needsConstraintReplay[driverName] {
			for _, constraintEntry := range cacheEntry.constraints {
				cstr := constraintEntry.getConstraint()
				if err := driver.AddConstraint(ctx, cstr); err != nil {
					return resp, fmt.Errorf("%w: while replaying constraints to driver %q", err, driverName)
				}
			}
			delete(cacheEntry.needsConstraintReplay, driverName)
		}
	}

	// This state mutation needs to happen after the new driver is fully ready
	// to enforce the template
	cacheEntry.Update(templ, crd, targetDrivers, targets...)

	// Remove old drivers last so that templates can be enforced
	// despite a botched update
	for oldDriverN := range cacheEntry.activeDrivers {
		if containsString(desiredDrivers, oldDriverN) {
			continue
		}
		oldDriver, ok := c.drivers[oldDriverN]
		if !ok {
			return resp, fmt.Errorf("%w: while changing drivers", clienterrors.ErrNoDriver)
		}
		removeTemplate := cachedCpy
		if removeTemplate == nil {
			removeTemplate = templ
		}
		if err := oldDriver.RemoveTemplate(ctx, removeTemplate); err != nil {
			return resp, fmt.Errorf("%w: while changing drivers", err)
		}
		delete(cacheEntry.activeDrivers, oldDriverN)
		delete(cacheEntry.needsConstraintReplay, oldDriverN)
	}

	for targetName := range targetDrivers {
		resp.Handled[targetName] = true
	}
	return resp, nil
}

func activeDriversMatch(template *templateClient, desired []string) bool {
	if len(template.activeDrivers) != len(desired) || len(template.needsConstraintReplay) != 0 {
		return false
	}
	for _, driverName := range desired {
		if !template.activeDrivers[driverName] {
			return false
		}
	}
	return true
}

func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

// RemoveTemplate removes the template source code from OPA and removes the CRD from the validation
// registry. Any constraints relying on the template will also be removed.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) RemoveTemplate(ctx context.Context, templ *templates.ConstraintTemplate) (*types.Responses, error) {
	resp := types.NewResponses()

	c.mtx.Lock()
	defer c.mtx.Unlock()

	name := templ.GetName()

	cached, found := c.templates[name]
	if !found {
		return resp, nil
	}

	template := cached.getTemplate()
	if template == nil {
		template = templ
	}

	// remove the template from all active drivers
	// to ensure cleanup in case of a botched update
	for driverN := range cached.activeDrivers {
		driver, ok := c.drivers[driverN]
		if !ok {
			return resp, fmt.Errorf("%w: could not clean up %q", clienterrors.ErrNoDriver, driverN)
		}

		err := driver.RemoveTemplate(ctx, template)
		if err != nil {
			return resp, err
		}
		delete(cached.activeDrivers, driverN)
	}

	delete(c.templates, name)

	for _, target := range cached.targets {
		resp.Handled[target.GetName()] = true
	}

	return resp, nil
}

func templateNotFound(name string) error {
	return fmt.Errorf("%w: template %q not found",
		ErrMissingConstraintTemplate, name)
}

// GetTemplate gets the currently recognized template.
func (c *Client) GetTemplate(templ *templates.ConstraintTemplate) (*templates.ConstraintTemplate, error) {
	name := templ.GetName()

	c.mtx.RLock()
	defer c.mtx.RUnlock()

	template := c.templates[name]
	if template == nil {
		return nil, templateNotFound(name)
	}

	if template.template == nil {
		return nil, templateNotFound(name)
	}

	return template.getTemplate(), nil
}

// getTemplateClientForKind returns the template entry for a given constraint.
func (c *Client) getTemplateClientForKind(kind string) *templateClient {
	name := strings.ToLower(kind)

	return c.templates[name]
}

// AddConstraint validates the constraint and, if valid, inserts it into OPA.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) (*types.Responses, error) {
	resp := types.NewResponses()

	c.mtx.Lock()
	defer c.mtx.Unlock()

	err := c.validateConstraint(constraint)
	if err != nil {
		return resp, err
	}

	kind := constraint.GetKind()
	cached := c.getTemplateClientForKind(kind)
	if cached == nil {
		templateName := strings.ToLower(kind)
		return resp, templateNotFound(templateName)
	}

	constraintWithDefaults, err := cached.ApplyDefaultParams(constraint)
	if err != nil {
		return resp, err
	}

	changed, err := cached.AddConstraint(constraintWithDefaults, c.enforcementPoints)
	if err != nil {
		return resp, err
	}

	if changed {
		for _, driverName := range driverNames(cached.targetDrivers) {
			driver, ok := c.drivers[driverName]
			if !ok {
				return resp, clienterrors.ErrNoDriver
			}
			if err = driver.AddConstraint(ctx, constraintWithDefaults); err != nil {
				return resp, err
			}
		}
	}

	for _, target := range cached.targets {
		resp.Handled[target.GetName()] = true
	}

	return resp, nil
}

// RemoveConstraint removes a constraint from OPA. On error, the responses
// return value will still be populated so that partial results can be analyzed.
func (c *Client) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) (*types.Responses, error) {
	resp := types.NewResponses()

	c.mtx.Lock()
	defer c.mtx.Unlock()

	err := validateConstraintMetadata(constraint)
	if err != nil {
		return resp, err
	}

	kind := constraint.GetKind()

	cached := c.getTemplateClientForKind(kind)
	if cached == nil {
		// The Template has been deleted, so nothing to do and no reason to return
		// error.
		return resp, nil
	}

	// Remove the constraint from all active drivers
	// in case we are in the middle of a botched update
	for driverN := range cached.activeDrivers {
		driver, ok := c.drivers[driverN]
		if !ok {
			return resp, clienterrors.ErrNoDriver
		}

		err = driver.RemoveConstraint(ctx, constraint)
		if err != nil {
			return nil, err
		}
	}

	for _, target := range cached.targets {
		resp.Handled[target.GetName()] = true
	}

	cached.RemoveConstraint(constraint.GetName())

	return resp, nil
}

// GetConstraint gets the currently recognized constraint.
func (c *Client) GetConstraint(constraint *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	err := validateConstraintMetadata(constraint)
	if err != nil {
		return nil, err
	}

	c.mtx.RLock()
	defer c.mtx.RUnlock()

	kind := constraint.GetKind()
	template := c.getTemplateClientForKind(kind)
	if template == nil {
		templateName := strings.ToLower(kind)
		return nil, templateNotFound(templateName)
	}

	return template.GetConstraint(constraint.GetName())
}

func validateConstraintMetadata(constraint *unstructured.Unstructured) error {
	if constraint.GetName() == "" {
		return fmt.Errorf("%w: missing metadata.name", apiconstraints.ErrInvalidConstraint)
	}

	gk := constraint.GroupVersionKind()
	if gk.Kind == "" {
		return fmt.Errorf("%w: missing kind", apiconstraints.ErrInvalidConstraint)
	}

	if gk.Group != apiconstraints.Group {
		return fmt.Errorf("%w: wrong API Group for Constraint %q, got %q but need %q",
			apiconstraints.ErrInvalidConstraint, constraint.GetName(), gk.Group, apiconstraints.Group)
	}

	return nil
}

func (c *Client) validateConstraint(constraint *unstructured.Unstructured) error {
	err := validateConstraintMetadata(constraint)
	if err != nil {
		return err
	}

	kind := constraint.GetKind()
	template := c.getTemplateClientForKind(kind)
	if template == nil {
		templateName := strings.ToLower(kind)
		return templateNotFound(templateName)
	}

	return template.ValidateConstraint(constraint)
}

// ValidateConstraint returns an error if the constraint is not recognized or does not conform to
// the registered CRD for that constraint.
func (c *Client) ValidateConstraint(constraint *unstructured.Unstructured) error {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return c.validateConstraint(constraint)
}

// AddData inserts the provided data into OPA for every target that can handle the data.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) AddData(ctx context.Context, data interface{}) (*types.Responses, error) {
	// TODO(#189): Make AddData atomic across all Drivers/Targets.

	resp := types.NewResponses()
	errMap := make(clienterrors.ErrorMap)
	// The set of targets doesn't change after Client initialization, so it is safe
	// to forego locking here. Similarly, - the Driver locks itself on writing data
	// and no state outside of Driver is changed by this operation, so Client
	// needs no locking here.
	for name, target := range c.targets {
		handled, key, processedData, err := target.ProcessData(data)
		if err != nil {
			errMap[name] = err
			continue
		}
		if !handled {
			continue
		}

		// Round trip data to force untyped JSON, as drivers are not type-aware.
		// Marshal first to reject invalid JSON values, then use OPA's JSON decoder
		// to preserve numeric precision by decoding numbers as json.Number instead
		// of float64.
		bytes, err := json.Marshal(processedData)
		if err != nil {
			errMap[name] = err

			continue
		}
		var processedDataCpy interface{}
		err = util.UnmarshalJSON(bytes, &processedDataCpy)
		if err != nil {
			errMap[name] = err

			continue
		}

		var cache handler.Cache
		if cacher, ok := target.(handler.Cacher); ok {
			cache = cacher.GetCache()
		}

		// Add to the target cache first because cache.Remove cannot fail. Thus, we
		// can prevent the system from getting into an inconsistent state.
		if cache != nil {
			err = cache.Add(key, processedData)
			if err != nil {
				// Use a different key than the driver to avoid clobbering errors.
				errMap[name] = err

				continue
			}
		}

		// To avoid maintaining duplicate caches, only Rego should get its own
		// storage. We should work to remove the need for this special case
		// by building a global storage object. Right now Rego needs its own
		// cache to cache constraints.
		if _, ok := c.drivers[regoSchema.Name]; ok {
			err = c.drivers[regoSchema.Name].AddData(ctx, name, key, processedDataCpy)
			if err != nil {
				errMap[name] = err

				if cache != nil {
					cache.Remove(key)
				}
				continue
			}
		} else if !c.ignoreNoReferentialDriverWarning {
			errMap[name] = ErrNoReferentialDriver
		}

		resp.Handled[name] = true
	}

	if len(errMap) == 0 {
		return resp, nil
	}
	return resp, &errMap
}

// RemoveData removes data from OPA for every target that can handle the data.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) RemoveData(ctx context.Context, data interface{}) (*types.Responses, error) {
	resp := types.NewResponses()
	errMap := make(clienterrors.ErrorMap)
	// Similar to AddData - no locking is required here. See AddData for full
	// explanation.
	for target, h := range c.targets {
		handled, relPath, _, err := h.ProcessData(data)
		if err != nil {
			errMap[target] = err
			continue
		}
		if !handled {
			continue
		}

		// To avoid maintaining duplicate caches, only Rego should get its own
		// storage. We should work to remove the need for this special case
		// by building a global storage object. Right now Rego needs its own
		// cache to cache constraints.
		if _, ok := c.drivers[regoSchema.Name]; ok {
			err = c.drivers[regoSchema.Name].RemoveData(ctx, target, relPath)
			if err != nil {
				errMap[target] = err
				continue
			}
		} else if !c.ignoreNoReferentialDriverWarning {
			errMap[target] = ErrNoReferentialDriver
		}

		resp.Handled[target] = true

		if cacher, ok := h.(handler.Cacher); ok {
			cache := cacher.GetCache()
			if cache != nil {
				cache.Remove(relPath)
			}
		}
	}

	if len(errMap) == 0 {
		return resp, nil
	}

	return resp, &errMap
}

func (c *Client) actionKey(constraint *unstructured.Unstructured) string {
	return fmt.Sprintf("%s.%s", constraint.GetKind(), constraint.GetName())
}

// Review makes sure the provided object satisfies constraints applicable for specific enforcement points.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) Review(ctx context.Context, obj interface{}, opts ...reviews.ReviewOpt) (*types.Responses, error) {
	var eps []string
	cfg := &reviews.ReviewCfg{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.EnforcementPoint == "" {
		cfg.EnforcementPoint = apiconstraints.AllEnforcementPoints
	}
	for _, ep := range c.enforcementPoints {
		if cfg.EnforcementPoint == apiconstraints.AllEnforcementPoints || cfg.EnforcementPoint == ep {
			eps = append(eps, ep)
		}
	}
	if eps == nil {
		return nil, fmt.Errorf("%w, supported enforcement points: %v", ErrUnsupportedEnforcementPoints, c.enforcementPoints)
	}

	responses := types.NewResponses()
	errMap := make(clienterrors.ErrorMap)

	ignoredTargets := make(map[string]bool)
	reviews := make(map[string]interface{})
	// The set of targets should not change after Client is initialized, so it
	// is safe to defer locking until after reviews have been created.
	for name, target := range c.targets {
		handled, review, err := target.HandleReview(obj)
		if err != nil {
			errMap.Add(name, fmt.Errorf("%w for target %q: %v", ErrReview, name, err))
			continue
		}

		if !handled {
			ignoredTargets[name] = true
			continue
		}

		reviews[name] = review
	}

	constraintsByTarget := make(map[string][]*unstructured.Unstructured)
	autorejections := make(map[string][]constraintMatchResult)
	scopedEnforcementActionsByTarget := make(map[string]map[string][]string)
	enforcementActionByTarget := make(map[string]map[string]string)

	c.mtx.RLock()
	defer c.mtx.RUnlock()

	for target, review := range reviews {
		var targetConstraints []*unstructured.Unstructured
		targetScopedEnforcementActions := make(map[string][]string)
		targetEnforcementAction := make(map[string]string)
		for _, template := range c.templates {
			if template.template == nil {
				continue
			}
			if cfg.EnforcementPoint == apiconstraints.WebhookEnforcementPoint {
				if arGetter, ok := review.(ARGetter); ok {
					req := arGetter.GetAdmissionRequest()
					if !template.MatchesOperation(target, string(req.Operation)) {
						continue
					}
				}
			}
			matchingConstraints := template.Matches(target, review, eps)
			for _, matchResult := range matchingConstraints {
				if matchResult.error == nil {
					targetConstraints = append(targetConstraints, matchResult.constraint)
					targetScopedEnforcementActions[c.actionKey(matchResult.constraint)] = matchResult.scopedEnforcementActions
					targetEnforcementAction[c.actionKey(matchResult.constraint)] = matchResult.enforcementAction
				} else {
					autorejections[target] = append(autorejections[target], matchResult)
				}
			}
		}
		constraintsByTarget[target] = targetConstraints
		scopedEnforcementActionsByTarget[target] = targetScopedEnforcementActions
		enforcementActionByTarget[target] = targetEnforcementAction
	}

	for target, review := range reviews {
		constraints := constraintsByTarget[target]

		resp, stats, err := c.review(ctx, target, constraints, review, opts...)
		if err != nil {
			errMap.Add(target, err)
			continue
		}

		for i := range resp.Results {
			if val, ok := scopedEnforcementActionsByTarget[target][c.actionKey(resp.Results[i].Constraint)]; ok {
				resp.Results[i].ScopedEnforcementActions = val
			}
			if val, ok := enforcementActionByTarget[target][c.actionKey(resp.Results[i].Constraint)]; ok {
				resp.Results[i].EnforcementAction = val
			}
		}

		for _, autorejection := range autorejections[target] {
			resp.AddResult(autorejection.ToResult())
		}

		// Ensure deterministic result ordering.
		resp.Sort()

		responses.ByTarget[target] = resp
		if stats != nil {
			// add the target label to these stats for future collation.
			targetLabel := &instrumentation.Label{Name: "target", Value: target}
			for _, stat := range stats {
				if len(stat.Labels) == 0 {
					stat.Labels = []*instrumentation.Label{targetLabel}
				} else {
					stat.Labels = append(stat.Labels, targetLabel)
				}
			}
			responses.StatsEntries = append(responses.StatsEntries, stats...)
		}
	}

	if len(errMap) == 0 {
		return responses, nil
	}

	return responses, &errMap
}

func (c *Client) review(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...reviews.ReviewOpt) (*types.Response, []*instrumentation.StatsEntry, error) {
	var results []*types.Result
	var stats []*instrumentation.StatsEntry
	var tracesBuilder strings.Builder
	errs := &clienterrors.ErrorMap{}

	driverToConstraints := map[string][]*unstructured.Unstructured{}

	for _, constraint := range constraints {
		template, ok := c.templates[strings.ToLower(constraint.GetObjectKind().GroupVersionKind().Kind)]
		if !ok {
			return nil, nil, fmt.Errorf("%w: while loading driver for constraint %s", ErrMissingConstraintTemplate, constraint.GetName())
		}
		driver := template.driverForTarget(target)
		if driver == "" {
			return nil, nil, fmt.Errorf("%w: while loading driver for constraint %s", clienterrors.ErrNoDriver, constraint.GetName())
		}
		driverToConstraints[driver] = append(driverToConstraints[driver], constraint)
	}

	for driverName, driver := range c.drivers {
		if len(driverToConstraints[driverName]) == 0 {
			continue
		}
		qr, err := driver.Query(ctx, target, driverToConstraints[driverName], review, opts...)
		if err != nil {
			errs.Add(driverName, err)
			continue
		}
		if qr != nil {
			results = append(results, qr.Results...)

			stats = append(stats, qr.StatsEntries...)

			if qr.Trace != nil {
				fmt.Fprintf(&tracesBuilder, "DRIVER %s:\n\n", driverName)
				tracesBuilder.WriteString(*qr.Trace)
				tracesBuilder.WriteString("\n\n")
			}
		}
	}

	traceStr := tracesBuilder.String()
	var trace *string
	if len(traceStr) != 0 {
		trace = &traceStr
	}

	// golang idiom is nil on no errors, so we should
	// only return errs if it is non-empty, otherwise
	// we get a non-nil interface (even if errs is nil, since
	// the interface would still hold type info).
	var errRet error
	if len(*errs) > 0 {
		errRet = errs
	}

	return &types.Response{
		Trace:   trace,
		Target:  target,
		Results: results,
	}, stats, errRet
}

// Dump dumps the state of OPA to aid in debugging.
func (c *Client) Dump(ctx context.Context) (string, error) {
	var dumpBuilder strings.Builder
	for driverName, driver := range c.drivers {
		dump, err := driver.Dump(ctx)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&dumpBuilder, "DRIVER: %s:\n\n", driverName)
		dumpBuilder.WriteString(dump)
		dumpBuilder.WriteString("\n\n")
	}
	return dumpBuilder.String(), nil
}

// GetDescriptionForStat returns a human-readable description for a given stat name.
func (c *Client) GetDescriptionForStat(source instrumentation.Source, statName string) string {
	if source.Type != instrumentation.EngineSourceType {
		// only handle engine source for now
		return instrumentation.UnknownDescription
	}

	driver, ok := c.drivers[source.Value]
	if !ok {
		return instrumentation.UnknownDescription
	}

	desc, err := driver.GetDescriptionForStat(statName)
	if err != nil {
		return instrumentation.UnknownDescription
	}

	return desc
}

// knownTargets returns a sorted list of known target names.
func (c *Client) knownTargets() []string {
	var knownTargets []string
	for known := range c.targets {
		knownTargets = append(knownTargets, known)
	}
	sort.Strings(knownTargets)

	return knownTargets
}

// getTargetHandlers returns the TargetHandlers for the Template, or an error if
// any target does not exist.
//
// The set of targets is assumed to be constant.
func (c *Client) getTargetHandlers(templ *templates.ConstraintTemplate) ([]handler.TargetHandler, error) {
	if err := crds.ValidateTargets(templ); err != nil {
		return nil, err
	}

	handlers := make([]handler.TargetHandler, 0, len(templ.Spec.Targets))
	for _, target := range templ.Spec.Targets {
		targetHandler, found := c.targets[target.Target]
		if !found {
			return nil, fmt.Errorf("%w: target %q not recognized, known targets %v",
				clienterrors.ErrInvalidConstraintTemplate, target.Target, c.knownTargets())
		}
		handlers = append(handlers, targetHandler)
	}
	return handlers, nil
}

// createCRD creates the Template's CRD and validates the result.
func createCRD(ctx context.Context, templ *templates.ConstraintTemplate, targets ...handler.TargetHandler) (*apiextensions.CustomResourceDefinition, error) {
	providers := make([]crds.MatchSchemaProvider, len(targets))
	for i, target := range targets {
		providers[i] = target
	}
	sch, err := crds.CreateSchemaForTargets(templ, providers...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrInvalidConstraintTemplate, err)
	}

	crd, err := crds.CreateCRD(templ, sch)
	if err != nil {
		return nil, err
	}

	err = crds.ValidateCRD(ctx, crd)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrInvalidConstraintTemplate, err)
	}

	return crd, nil
}

func validateTemplateMetadata(templ *templates.ConstraintTemplate) error {
	kind := templ.Spec.CRD.Spec.Names.Kind
	if kind == "" {
		return fmt.Errorf("%w: ConstraintTemplate %q does not specify CRD Kind",
			clienterrors.ErrInvalidConstraintTemplate, templ.GetName())
	}

	if !strings.EqualFold(templ.Name, kind) {
		return fmt.Errorf("%w: the ConstraintTemplate's name %q is not equal to the lowercase of CRD's Kind: %q",
			clienterrors.ErrInvalidConstraintTemplate, templ.Name, strings.ToLower(kind))
	}

	return nil
}
