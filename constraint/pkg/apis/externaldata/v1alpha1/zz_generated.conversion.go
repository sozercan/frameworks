// +build !ignore_autogenerated

/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	externaldata "github.com/open-policy-agent/frameworks/constraint/pkg/core/externaldata"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*ExternalData)(nil), (*externaldata.ExternalData)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_ExternalData_To_externaldata_ExternalData(a.(*ExternalData), b.(*externaldata.ExternalData), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*externaldata.ExternalData)(nil), (*ExternalData)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_externaldata_ExternalData_To_v1alpha1_ExternalData(a.(*externaldata.ExternalData), b.(*ExternalData), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*ExternalDataList)(nil), (*externaldata.ExternalDataList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_ExternalDataList_To_externaldata_ExternalDataList(a.(*ExternalDataList), b.(*externaldata.ExternalDataList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*externaldata.ExternalDataList)(nil), (*ExternalDataList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_externaldata_ExternalDataList_To_v1alpha1_ExternalDataList(a.(*externaldata.ExternalDataList), b.(*ExternalDataList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*ExternalDataSpec)(nil), (*externaldata.ExternalDataSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_ExternalDataSpec_To_externaldata_ExternalDataSpec(a.(*ExternalDataSpec), b.(*externaldata.ExternalDataSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*externaldata.ExternalDataSpec)(nil), (*ExternalDataSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_externaldata_ExternalDataSpec_To_v1alpha1_ExternalDataSpec(a.(*externaldata.ExternalDataSpec), b.(*ExternalDataSpec), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_ExternalData_To_externaldata_ExternalData(in *ExternalData, out *externaldata.ExternalData, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_ExternalDataSpec_To_externaldata_ExternalDataSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_ExternalData_To_externaldata_ExternalData is an autogenerated conversion function.
func Convert_v1alpha1_ExternalData_To_externaldata_ExternalData(in *ExternalData, out *externaldata.ExternalData, s conversion.Scope) error {
	return autoConvert_v1alpha1_ExternalData_To_externaldata_ExternalData(in, out, s)
}

func autoConvert_externaldata_ExternalData_To_v1alpha1_ExternalData(in *externaldata.ExternalData, out *ExternalData, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_externaldata_ExternalDataSpec_To_v1alpha1_ExternalDataSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_externaldata_ExternalData_To_v1alpha1_ExternalData is an autogenerated conversion function.
func Convert_externaldata_ExternalData_To_v1alpha1_ExternalData(in *externaldata.ExternalData, out *ExternalData, s conversion.Scope) error {
	return autoConvert_externaldata_ExternalData_To_v1alpha1_ExternalData(in, out, s)
}

func autoConvert_v1alpha1_ExternalDataList_To_externaldata_ExternalDataList(in *ExternalDataList, out *externaldata.ExternalDataList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]externaldata.ExternalData)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1alpha1_ExternalDataList_To_externaldata_ExternalDataList is an autogenerated conversion function.
func Convert_v1alpha1_ExternalDataList_To_externaldata_ExternalDataList(in *ExternalDataList, out *externaldata.ExternalDataList, s conversion.Scope) error {
	return autoConvert_v1alpha1_ExternalDataList_To_externaldata_ExternalDataList(in, out, s)
}

func autoConvert_externaldata_ExternalDataList_To_v1alpha1_ExternalDataList(in *externaldata.ExternalDataList, out *ExternalDataList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]ExternalData)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_externaldata_ExternalDataList_To_v1alpha1_ExternalDataList is an autogenerated conversion function.
func Convert_externaldata_ExternalDataList_To_v1alpha1_ExternalDataList(in *externaldata.ExternalDataList, out *ExternalDataList, s conversion.Scope) error {
	return autoConvert_externaldata_ExternalDataList_To_v1alpha1_ExternalDataList(in, out, s)
}

func autoConvert_v1alpha1_ExternalDataSpec_To_externaldata_ExternalDataSpec(in *ExternalDataSpec, out *externaldata.ExternalDataSpec, s conversion.Scope) error {
	out.ProxyURL = in.ProxyURL
	out.FailurePolicy = in.FailurePolicy
	out.Timeout = in.Timeout
	out.MaxRetry = in.MaxRetry
	return nil
}

// Convert_v1alpha1_ExternalDataSpec_To_externaldata_ExternalDataSpec is an autogenerated conversion function.
func Convert_v1alpha1_ExternalDataSpec_To_externaldata_ExternalDataSpec(in *ExternalDataSpec, out *externaldata.ExternalDataSpec, s conversion.Scope) error {
	return autoConvert_v1alpha1_ExternalDataSpec_To_externaldata_ExternalDataSpec(in, out, s)
}

func autoConvert_externaldata_ExternalDataSpec_To_v1alpha1_ExternalDataSpec(in *externaldata.ExternalDataSpec, out *ExternalDataSpec, s conversion.Scope) error {
	out.ProxyURL = in.ProxyURL
	out.FailurePolicy = in.FailurePolicy
	out.Timeout = in.Timeout
	out.MaxRetry = in.MaxRetry
	return nil
}

// Convert_externaldata_ExternalDataSpec_To_v1alpha1_ExternalDataSpec is an autogenerated conversion function.
func Convert_externaldata_ExternalDataSpec_To_v1alpha1_ExternalDataSpec(in *externaldata.ExternalDataSpec, out *ExternalDataSpec, s conversion.Scope) error {
	return autoConvert_externaldata_ExternalDataSpec_To_v1alpha1_ExternalDataSpec(in, out, s)
}