package crds

import (
	"fmt"
	"sort"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/utils/ptr"
)

// CreateSchema combines the schema of the match target and the ConstraintTemplate parameters
// to form the schema of the actual constraint resource.
func CreateSchema(templ *templates.ConstraintTemplate, target MatchSchemaProvider) *apiextensions.JSONSchemaProps {
	return createSchema(templ, target.MatchSchema())
}

// CreateSchemaForTargets combines every target's match schema with the
// ConstraintTemplate parameter schema. A Constraint is shared by all targets,
// so overlapping fields are intersected while target-specific fields are
// retained.
func CreateSchemaForTargets(templ *templates.ConstraintTemplate, targets ...MatchSchemaProvider) (*apiextensions.JSONSchemaProps, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no target match schemas provided")
	}

	first := targets[0].MatchSchema()
	match := first.DeepCopy()
	for i := 1; i < len(targets); i++ {
		next := targets[i].MatchSchema()
		if err := mergeSchema(match, &next, "match"); err != nil {
			return nil, err
		}
	}

	return createSchema(templ, *match), nil
}

func createSchema(templ *templates.ConstraintTemplate, match apiextensions.JSONSchemaProps) *apiextensions.JSONSchemaProps {
	defaultEnforcementAction := apiextensions.JSON("deny")
	props := map[string]apiextensions.JSONSchemaProps{
		"match":             match,
		"enforcementAction": {Type: "string", Default: &defaultEnforcementAction},
		"scopedEnforcementActions": {
			Type:    "array",
			Default: nil,
			Items: &apiextensions.JSONSchemaPropsOrArray{
				Schema: &apiextensions.JSONSchemaProps{
					Type: "object",
					Properties: map[string]apiextensions.JSONSchemaProps{
						"action": {Type: "string"},
						"enforcementPoints": {
							Type: "array",
							Items: &apiextensions.JSONSchemaPropsOrArray{
								Schema: &apiextensions.JSONSchemaProps{
									Type: "object",
									Properties: map[string]apiextensions.JSONSchemaProps{
										"name": {Type: "string"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if templ.Spec.CRD.Spec.Validation != nil && templ.Spec.CRD.Spec.Validation.OpenAPIV3Schema != nil {
		internalSchema := *templ.Spec.CRD.Spec.Validation.OpenAPIV3Schema.DeepCopy()
		props["parameters"] = internalSchema
	}

	schema := &apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"metadata": {
				Type: "object",
				Properties: map[string]apiextensions.JSONSchemaProps{
					"name": {
						Type:      "string",
						MaxLength: ptr.To[int64](63),
					},
				},
			},
			"spec": {
				Type:       "object",
				Properties: props,
			},
			"status": {
				XPreserveUnknownFields: ptr.To[bool](true),
			},
		},
	}

	return schema
}

func mergeSchema(dst, src *apiextensions.JSONSchemaProps, path string) error {
	if dst.Type == "" {
		dst.Type = src.Type
	} else if src.Type != "" && dst.Type != src.Type {
		return fmt.Errorf("incompatible target match schemas at %s: types %q and %q", path, dst.Type, src.Type)
	}

	if dst.Properties == nil && len(src.Properties) != 0 {
		dst.Properties = make(map[string]apiextensions.JSONSchemaProps, len(src.Properties))
	}
	for name, srcProperty := range src.Properties {
		dstProperty, found := dst.Properties[name]
		if !found {
			dst.Properties[name] = *srcProperty.DeepCopy()
			continue
		}
		if err := mergeSchema(&dstProperty, &srcProperty, path+"."+name); err != nil {
			return err
		}
		dst.Properties[name] = dstProperty
	}

	dst.Required = unionStrings(dst.Required, src.Required)
	dst.Enum = intersectEnum(dst.Enum, src.Enum)
	dst.MinLength = maxInt64Ptr(dst.MinLength, src.MinLength)
	dst.MaxLength = minInt64Ptr(dst.MaxLength, src.MaxLength)
	dst.MinItems = maxInt64Ptr(dst.MinItems, src.MinItems)
	dst.MaxItems = minInt64Ptr(dst.MaxItems, src.MaxItems)

	if dst.Items == nil && src.Items != nil {
		dst.Items = src.Items.DeepCopy()
	} else if dst.Items != nil && src.Items != nil && dst.Items.Schema != nil && src.Items.Schema != nil {
		if err := mergeSchema(dst.Items.Schema, src.Items.Schema, path+"[]"); err != nil {
			return err
		}
	}

	if dst.AdditionalProperties == nil && src.AdditionalProperties != nil {
		dst.AdditionalProperties = src.AdditionalProperties.DeepCopy()
	} else if dst.AdditionalProperties != nil && src.AdditionalProperties != nil {
		dst.AdditionalProperties.Allows = dst.AdditionalProperties.Allows && src.AdditionalProperties.Allows
		if dst.AdditionalProperties.Schema == nil {
			dst.AdditionalProperties.Schema = src.AdditionalProperties.Schema.DeepCopy()
		} else if src.AdditionalProperties.Schema != nil {
			if err := mergeSchema(dst.AdditionalProperties.Schema, src.AdditionalProperties.Schema, path+".*"); err != nil {
				return err
			}
		}
	}

	return nil
}

func unionStrings(left, right []string) []string {
	set := make(map[string]struct{}, len(left)+len(right))
	for _, value := range left {
		set[value] = struct{}{}
	}
	for _, value := range right {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func intersectEnum(left, right []apiextensions.JSON) []apiextensions.JSON {
	if len(left) == 0 {
		return append([]apiextensions.JSON(nil), right...)
	}
	if len(right) == 0 {
		return left
	}
	result := make([]apiextensions.JSON, 0, len(left))
	for _, candidate := range left {
		for _, other := range right {
			if fmt.Sprint(candidate) == fmt.Sprint(other) {
				result = append(result, candidate)
				break
			}
		}
	}
	return result
}

func maxInt64Ptr(left, right *int64) *int64 {
	if left == nil {
		return right
	}
	if right == nil || *left >= *right {
		return left
	}
	return right
}

func minInt64Ptr(left, right *int64) *int64 {
	if left == nil {
		return right
	}
	if right == nil || *left <= *right {
		return left
	}
	return right
}
