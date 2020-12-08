// Copyright 2013 Apcera Inc. All rights reserved.

package gssapi

/*
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

OM_uint32
wrap_gss_acquire_cred(void *fp,
	OM_uint32 * minor_status,
	const gss_name_t desired_name,
	OM_uint32 time_req,
	const gss_OID_set desired_mechs,
	gss_cred_usage_t cred_usage,
	gss_cred_id_t * output_cred_handle,
	gss_OID_set * actual_mechs,
	OM_uint32 * time_rec)
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		const gss_name_t,
		OM_uint32,
		const gss_OID_set,
		gss_cred_usage_t,
		gss_cred_id_t *,
		gss_OID_set *,
		OM_uint32 *)
	) fp)(
		minor_status,
		desired_name,
		time_req,
		desired_mechs,
		cred_usage,
		output_cred_handle,
		actual_mechs,
		time_rec);
}

OM_uint32
wrap_gss_add_cred(void *fp,
	OM_uint32 * minor_status,
	const gss_cred_id_t input_cred_handle,
	const gss_name_t desired_name,
	const gss_OID desired_mech,
	gss_cred_usage_t cred_usage,
	OM_uint32 initiator_time_req,
	OM_uint32 acceptor_time_req,
	gss_cred_id_t * output_cred_handle,
	gss_OID_set * actual_mechs,
	OM_uint32 * initiator_time_rec,
	OM_uint32 * acceptor_time_rec)
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		const gss_cred_id_t,
		const gss_name_t,
		const gss_OID,
		gss_cred_usage_t,
		OM_uint32,
		OM_uint32,
		gss_cred_id_t *,
		gss_OID_set *,
		OM_uint32 *,
		OM_uint32 *)
	) fp)(
		minor_status,
		input_cred_handle,
		desired_name,
		desired_mech,
		cred_usage,
		initiator_time_req,
		acceptor_time_req,
		output_cred_handle,
		actual_mechs,
		initiator_time_rec,
		acceptor_time_rec);
}

//Protocol transition
OM_uint32
wrap_gss_acquire_cred_impersonate_name(void *fp,
	OM_uint32 * minor_status,
	const gss_cred_id_t impersonator_cred_handle,
	const gss_name_t desired_name,
	OM_uint32 time_req,
	const gss_OID_set desired_mechs,
	gss_cred_usage_t cred_usage,
	gss_cred_id_t *output_cred_handle,
	gss_OID_set *actual_mechs,
	OM_uint32 *time_rec)
{
	return((OM_uint32(*) (OM_uint32 *,
		const gss_cred_id_t,
		const gss_name_t,
		OM_uint32,
		const gss_OID_set,
		gss_cred_usage_t,
		gss_cred_id_t *,
		gss_OID_set *,
		OM_uint32 *)
	) fp)(minor_status,
 		impersonator_cred_handle,
		desired_name,
		time_req,
		desired_mechs,
		cred_usage,
		output_cred_handle,
		actual_mechs,
		time_rec);
}

OM_uint32
wrap_gss_add_cred_impersonate_name(void *fp,
	OM_uint32 *minor_status,
	gss_cred_id_t input_cred_handle,
	const gss_cred_id_t impersonator_cred_handle,
	const gss_name_t desired_name,
	const gss_OID desired_mech,
	gss_cred_usage_t cred_usage,
	OM_uint32 initiator_time_req,
	OM_uint32 acceptor_time_req,
	gss_cred_id_t *output_cred_handle,
	gss_OID_set *actual_mechs,
	OM_uint32 *initiator_time_rec,
	OM_uint32 *acceptor_time_rec)
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		gss_cred_id_t,
		const gss_cred_id_t,
		const gss_name_t,
		const gss_OID,
		gss_cred_usage_t,
		OM_uint32,
		OM_uint32,
		gss_cred_id_t *,
		gss_OID_set *,
		OM_uint32 *,
		OM_uint32 *)
	) fp) (
		minor_status,
		input_cred_handle,
		impersonator_cred_handle,
		desired_name,
		desired_mech,
		cred_usage,
		initiator_time_req,
		acceptor_time_req,
		output_cred_handle,
		actual_mechs,
		initiator_time_rec,
		acceptor_time_rec
	);
}


OM_uint32
wrap_gss_inquire_cred (void *fp,
	OM_uint32           *minor_status,
	const gss_cred_id_t cred_handle,
	gss_name_t          *name,
	OM_uint32           *lifetime,
	gss_cred_usage_t    *cred_usage,
	gss_OID_set         *mechanisms )
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		const gss_cred_id_t,
		gss_name_t *,
		OM_uint32 *,
		gss_cred_usage_t *,
		gss_OID_set *)
	) fp)(
		minor_status,
		cred_handle,
		name,
		lifetime,
		cred_usage,
		mechanisms);
}

OM_uint32
wrap_gss_inquire_cred_by_mech (void *fp,
	OM_uint32           *minor_status,
	const gss_cred_id_t cred_handle,
	const gss_OID       mech_type,
	gss_name_t          *name,
	OM_uint32           *initiator_lifetime,
	OM_uint32           *acceptor_lifetime,
	gss_cred_usage_t    *cred_usage )
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		const gss_cred_id_t,
		const gss_OID,
		gss_name_t *,
		OM_uint32 *,
		OM_uint32 *,
		gss_cred_usage_t *)
	) fp)(
		minor_status,
		cred_handle,
		mech_type,
		name,
		initiator_lifetime,
		acceptor_lifetime,
		cred_usage);
}

OM_uint32
wrap_gss_release_cred(void *fp,
	OM_uint32		*minor_status,
	gss_cred_id_t	*cred_handle)
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		gss_cred_id_t *)
	) fp)(
		minor_status,
		cred_handle);
}

OM_uint32
wrap_gss_acquire_cred_from(void *fp,
    OM_uint32 *minor_status,
	gss_name_t desired_name,
	OM_uint32 time_req,
	gss_OID_set desired_mechs,
	gss_cred_usage_t cred_usage,
	gss_const_key_value_set_t cred_store,
	gss_cred_id_t *output_cred_handle,
	gss_OID_set *actual_mechs,
	OM_uint32 * time_rec)
{
	return ((OM_uint32(*) (
    	OM_uint32 *,
		gss_name_t,
		OM_uint32,
		gss_OID_set,
		gss_cred_usage_t,
		gss_const_key_value_set_t,
		gss_cred_id_t *,
		gss_OID_set *,
		OM_uint32 *)
	) fp) (minor_status,
		desired_name,
		time_req,
		desired_mechs,
		cred_usage,
		cred_store,
		output_cred_handle,
		actual_mechs,
		time_rec);
}

OM_uint32
wrap_gss_add_cred_from(void *fp,
	OM_uint32 *minor_status,
	gss_cred_id_t input_cred_handle,
	gss_name_t desired_name,
	gss_OID desired_mech,
	gss_cred_usage_t cred_usage,
	OM_uint32 initiator_time_req,
	OM_uint32 acceptor_time_req,
	gss_const_key_value_set_t cred_store,
	gss_cred_id_t *output_cred_handle,
	gss_OID_set *actual_mechs,
	OM_uint32 *initiator_time_rec,
	OM_uint32 *acceptor_time_rec)
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		gss_cred_id_t,
		gss_name_t,
		gss_OID,
		gss_cred_usage_t,
		OM_uint32,
		OM_uint32,
		gss_const_key_value_set_t,
		gss_cred_id_t *,
		gss_OID_set *,
		OM_uint32 *,
		OM_uint32 *)
	) fp) (
		minor_status,
		input_cred_handle,
		desired_name,
		desired_mech,
		cred_usage,
		initiator_time_req,
		acceptor_time_req,
		cred_store,
		output_cred_handle,
		actual_mechs,
		initiator_time_rec,
		acceptor_time_rec);
}

OM_uint32
wrap_gss_store_cred(void *fp,
	OM_uint32 *minor_status,
	const gss_cred_id_t input_cred_handle,
	gss_cred_usage_t input_usage,
	const gss_OID desired_mech,
	OM_uint32 overwrite_cred,
	OM_uint32 default_cred,
	gss_OID_set *elements_stored,
	gss_cred_usage_t *cred_usage_stored)
{
	return ((OM_uint32(*)(
		OM_uint32 *,
		const gss_cred_id_t,
		gss_cred_usage_t,
		const gss_OID,
		OM_uint32,
		OM_uint32,
		gss_OID_set *,
		gss_cred_usage_t *)
	) fp) (minor_status,
		input_cred_handle,
		input_usage,
		desired_mech,
		overwrite_cred,
		default_cred,
		elements_stored,
		cred_usage_stored
	);
}

OM_uint32
wrap_gss_store_cred_into(void *fp,
	OM_uint32 *minor_status,
	gss_cred_id_t input_cred_handle,
	gss_cred_usage_t input_usage,
	gss_OID desired_mech,
	OM_uint32 overwrite_cred,
	OM_uint32 default_cred,
	gss_const_key_value_set_t cred_store,
	gss_OID_set *elements_stored,
	gss_cred_usage_t *cred_usage_stored)
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		gss_cred_id_t ,
		gss_cred_usage_t,
		gss_OID,
		OM_uint32,
		OM_uint32,
		gss_const_key_value_set_t,
		gss_OID_set *,
		gss_cred_usage_t *)
	) fp) (
		minor_status,
		input_cred_handle,
		input_usage,
		desired_mech,
		overwrite_cred,
		default_cred,
		cred_store,
		elements_stored,
		cred_usage_stored);
}

OM_uint32
wrap_gss_import_cred(void *fp,
	OM_uint32		*minor_status,
	gss_buffer_t	cred_token,
	gss_cred_id_t	*cred_handle)
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		gss_buffer_t,
		gss_cred_id_t *)
	) fp)(
		minor_status,
		cred_token,
		cred_handle);
}

OM_uint32
wrap_gss_export_cred (void* fp,
	OM_uint32		*minor_status,
	gss_cred_id_t	cred_handle,
	gss_buffer_t	cred_token)
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		gss_cred_id_t,
		gss_buffer_t)
	) fp) (
		minor_status,
		cred_handle,
		cred_token);
}

OM_uint32
wrap_gss_acquire_cred_with_password (void *fp,
	OM_uint32 *minor_status,
	gss_const_name_t desired_name,
	const gss_buffer_t password,
	OM_uint32 time_req,
	const gss_OID_set desired_mechs,
	gss_cred_usage_t cred_usage,
	gss_cred_id_t *output_cred_handle,
	gss_OID_set *actual_mechs,
	OM_uint32 *time_rec
	)
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		gss_const_name_t,
		const gss_buffer_t,
		OM_uint32,
		const gss_OID_set,
		gss_cred_usage_t,
		gss_cred_id_t *,
		gss_OID_set *,
		OM_uint32 *)
	) fp) (
		minor_status,
		desired_name,
		password,
		time_req,
		desired_mechs,
		cred_usage,
		output_cred_handle,
		actual_mechs,
		time_rec
		);
}

OM_uint32
wrap_gss_add_cred_with_password (void *fp,
            OM_uint32 *minor_status,
            gss_const_cred_id_t input_cred_handle,
            gss_const_name_t desired_name,
            const gss_OID desired_mech,
            const gss_buffer_t password,
            gss_cred_usage_t cred_usage,
            OM_uint32 initiator_time_req,
            OM_uint32 acceptor_time_req,
            gss_cred_id_t *output_cred_handle,
            gss_OID_set *actual_mechs,
            OM_uint32 *initiator_time_rec,
            OM_uint32 *acceptor_time_rec
           )
{
	return ((OM_uint32(*) (
		OM_uint32 *,
		gss_const_cred_id_t,
		gss_const_name_t,
		const gss_OID,
		const gss_buffer_t,
		gss_cred_usage_t,
		OM_uint32,
		OM_uint32,
		gss_cred_id_t *,
		gss_OID_set *,
		OM_uint32 *,
		OM_uint32 *)
	) fp) (
		minor_status,
		input_cred_handle,
		desired_name,
		desired_mech,
		password,
		cred_usage,
		initiator_time_req,
		acceptor_time_req,
		output_cred_handle,
		actual_mechs,
		initiator_time_rec,
		acceptor_time_rec
		);
}

OM_uint32 wrap_gss_inquire_cred_by_oid(void* fp,
	OM_uint32 *minor_status,
	const gss_cred_id_t cred_handle,
	const gss_OID desired_object,
	gss_buffer_set_t *data_set)
{
	return ((OM_uint32(*) (
		OM_uint32*,
		const gss_cred_id_t,
		const gss_OID,
		gss_buffer_set_t*)
	) fp)(minor_status, cred_handle, desired_object, data_set);
}

*/
import "C"

import (
	"C"
	"fmt"
	"time"
)

// NewCredId instantiates a new credential.
func (lib *Lib) NewCredId() *CredId {
	return &CredId{
		lib: lib,
	}
}

// AcquireCred implements gss_acquire_cred API, as per
// https://tools.ietf.org/html/rfc2743#page-31. outputCredHandle, actualMechs
// must be .Release()-ed by the caller
func (lib *Lib) AcquireCred(desiredName *Name, timeReq time.Duration,
	desiredMechs *OIDSet, credUsage CredUsage) (outputCredHandle *CredId,
	actualMechs *OIDSet, timeRec time.Duration, err error) {

	min := C.OM_uint32(0)
	timerec := C.OM_uint32(0)
	cCredHandle := C.gss_cred_id_t(nil)
	cOIDSet := C.gss_OID_set(nil)
	var name C.gss_name_t
	if desiredName != nil {
		name = desiredName.C_gss_name_t
	} else {
		name = nil
	}
	maj := C.wrap_gss_acquire_cred(lib.Fp_gss_acquire_cred,
		&min,
		name,
		C.OM_uint32(timeReq.Seconds()),
		desiredMechs.C_gss_OID_set,
		C.gss_cred_usage_t(credUsage),
		&cCredHandle,
		&cOIDSet,
		&timerec)

	err = lib.stashLastStatus(maj, min)
	if err == nil {
		actualMechs = lib.NewOIDSet()
		actualMechs.C_gss_OID_set = cOIDSet
		outputCredHandle = lib.NewCredId()
		outputCredHandle.C_gss_cred_id_t = cCredHandle
	}

	return
}

// AddCred implements gss_add_cred API, as per
// https://tools.ietf.org/html/rfc2743#page-36. outputCredHandle, actualMechs
// must be .Release()-ed by the caller
func (lib *Lib) AddCred(inputCredHandle *CredId,
	desiredName *Name, desiredMech *OID, credUsage CredUsage,
	initiatorTimeReq time.Duration, acceptorTimeReq time.Duration) (
	outputCredHandle *CredId, actualMechs *OIDSet,
	initiatorTimeRec time.Duration, acceptorTimeRec time.Duration,
	err error) {

	min := C.OM_uint32(0)
	actualMechs = lib.NewOIDSet()
	outputCredHandle = lib.NewCredId()
	initSeconds := C.OM_uint32(0)
	acceptSeconds := C.OM_uint32(0)

	maj := C.wrap_gss_add_cred(lib.Fp_gss_add_cred,
		&min,
		inputCredHandle.C_gss_cred_id_t,
		desiredName.C_gss_name_t,
		desiredMech.C_gss_OID,
		C.gss_cred_usage_t(credUsage),
		C.OM_uint32(initiatorTimeReq.Seconds()),
		C.OM_uint32(acceptorTimeReq.Seconds()),
		&outputCredHandle.C_gss_cred_id_t,
		&actualMechs.C_gss_OID_set,
		&initSeconds,
		&acceptSeconds)

	err = lib.stashLastStatus(maj, min)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	return outputCredHandle,
		actualMechs,
		time.Duration(initSeconds) * time.Second,
		time.Duration(acceptSeconds) * time.Second,
		nil
}

// AcquireCredImpersonateName implements gss_acquire_cred_impersonate_name
// API, as per https://tools.ietf.org/html/rfc2743#page-31. outputCredHandle,
// actualMechs must be .Release()-ed by the caller
// TODO: find correct RFC.
func (lib *Lib) AcquireCredImpersonateName(impersonatorCredHandle *CredId,
	desiredName *Name, timeReq time.Duration, desiredMechs *OIDSet,
	credUsage CredUsage) (
	outputCredHandle *CredId, actualMechs *OIDSet, timeRec time.Duration,
	err error) {

	lib.Trace("*Lib.AcquireCredImpersonateName: enter\n")
	defer func(){lib.Trace(fmt.Sprintf("*Lib.AcquireCredImpersonateName: exit"))}()
	min := C.OM_uint32(0)
	cOIDSet := C.gss_OID_set(nil)
	cCred := C.gss_cred_id_t(nil)
	timerec := C.OM_uint32(0)

	maj := C.wrap_gss_acquire_cred_impersonate_name(lib.Fp_gss_acquire_cred_impersonate_name,
		&min,
		impersonatorCredHandle.C_gss_cred_id_t,
		desiredName.C_gss_name_t,
		C.OM_uint32(timeReq.Seconds()),
		desiredMechs.C_gss_OID_set,
		C.gss_cred_usage_t(credUsage),
		&cCred,
		&cOIDSet,
		&timerec)

	err = lib.stashLastStatus(maj, min)
	if err == nil {
		actualMechs = lib.NewOIDSet()
		actualMechs.C_gss_OID_set = cOIDSet
		outputCredHandle = lib.NewCredId()
		outputCredHandle.C_gss_cred_id_t = cCred
		timeRec = time.Duration(timerec) * time.Second
	} else {
		lib.Debug(fmt.Sprintf("*Lib.AcquireCredImpersonateName: gss_acquire_cred_impersonate_name returned error: %v", err))
	}

	return
}

// AddCredImpersonateName implements gss_add_cred_impersonate_name API, as per
// https://tools.ietf.org/html/rfc2743#page-36. outputCredHandle, actualMechs
// must be .Release()-ed by the caller
//TODO: find the right RFC.
func (lib *Lib) AddCredImpersonateName(inputCredHandle *CredId,
	impersonatorCredHandle *CredId, desiredName *Name, desiredMech *OID,
	credUsage CredUsage, initiatorTimeReq time.Duration, acceptorTimeReq time.Duration) (
	outputCredHandle *CredId, actualMechs *OIDSet, initiatorTimeRec time.Duration,
	acceptorTimeRec time.Duration, err error) {

	min := C.OM_uint32(0)
	cOIDSet := C.gss_OID_set(nil)
	cCred := C.gss_cred_id_t(nil)
	initSeconds := C.OM_uint32(0)
	acceptSeconds := C.OM_uint32(0)

	maj := C.wrap_gss_add_cred_impersonate_name(lib.Fp_gss_add_cred_impersonate_name,
		&min,
		impersonatorCredHandle.C_gss_cred_id_t,
		inputCredHandle.C_gss_cred_id_t,
		desiredName.C_gss_name_t,
		desiredMech.C_gss_OID,
		C.gss_cred_usage_t(credUsage),
		C.OM_uint32(initiatorTimeReq.Seconds()),
		C.OM_uint32(acceptorTimeReq.Seconds()),
		&cCred,
		&cOIDSet,
		&initSeconds,
		&acceptSeconds)

	err = lib.stashLastStatus(maj, min)
	if nil == err {
		actualMechs = lib.NewOIDSet()
		actualMechs.C_gss_OID_set = cOIDSet
		outputCredHandle = lib.NewCredId()
		outputCredHandle.C_gss_cred_id_t = cCred
		initiatorTimeRec = time.Duration(initSeconds) * time.Second
		acceptorTimeRec = time.Duration(acceptSeconds) * time.Second
	}

	return
}

// InquireCred implements gss_inquire_cred API, as per
// https://tools.ietf.org/html/rfc2743#page-34. name and mechanisms must be
// .Release()-ed by the caller
func (lib *Lib) InquireCred(credHandle *CredId) (
	name *Name, lifetime time.Duration, credUsage CredUsage, mechanisms *OIDSet,
	err error) {

	min := C.OM_uint32(0)
	name = lib.NewName()
	life := C.OM_uint32(0)
	credUsage = CredUsage(0)
	mechanisms = lib.NewOIDSet()

	maj := C.wrap_gss_inquire_cred(lib.Fp_gss_inquire_cred,
		&min,
		credHandle.C_gss_cred_id_t,
		&name.C_gss_name_t,
		&life,
		(*C.gss_cred_usage_t)(&credUsage),
		&mechanisms.C_gss_OID_set)
	err = lib.stashLastStatus(maj, min)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	return name,
		time.Duration(life) * time.Second,
		credUsage,
		mechanisms,
		nil
}

func (cred *CredId) Inquire() (
	name *Name, lifetime time.Duration, credUsage CredUsage, mechanisms *OIDSet,
	err error) {

	if cred == nil || cred.C_gss_cred_id_t == nil {
		err = ErrInvalidObject
		return
	}

	return cred.lib.InquireCred(cred)
}

// InquireCredByMech implements gss_inquire_cred_by_mech API, as per
// https://tools.ietf.org/html/rfc2743#page-39. name must be .Release()-ed by
// the caller
func (lib *Lib) InquireCredByMech(credHandle *CredId, mechType *OID) (
	name *Name, initiatorLifetime time.Duration, acceptorLifetime time.Duration,
	credUsage CredUsage, err error) {

	min := C.OM_uint32(0)
	name = lib.NewName()
	ilife := C.OM_uint32(0)
	alife := C.OM_uint32(0)
	credUsage = CredUsage(0)

	maj := C.wrap_gss_inquire_cred_by_mech(lib.Fp_gss_inquire_cred_by_mech,
		&min,
		credHandle.C_gss_cred_id_t,
		mechType.C_gss_OID,
		&name.C_gss_name_t,
		&ilife,
		&alife,
		(*C.gss_cred_usage_t)(&credUsage))
	err = lib.stashLastStatus(maj, min)
	if err != nil {
		return nil, 0, 0, 0, err
	}

	return name,
		time.Duration(ilife) * time.Second,
		time.Duration(alife) * time.Second,
		credUsage,
		nil
}

// InquireCredByMech implements gss_inquire_cred_by_mech API, as per
// https://tools.ietf.org/html/rfc2743#page-39. name must be .Release()-ed by
// the caller
func (lib *Lib) InquireCredByOID(credHandle *CredId, desiredObject *OID) ([][]byte, error) {
	return credHandle.InquireByOID(desiredObject)
}

func (cred *CredId) InquireByOID (desiredObject *OID) (dataSet [][]byte, err error) {
	if cred == nil || cred.C_gss_cred_id_t == nil {
		return
	}

	lib := cred.lib
	lib.Trace(fmt.Sprintf("Cred.InquireByOID: enter\n"))
	defer func(){lib.Trace(fmt.Sprintf("Cred.InquireByOID: exit\n"))}()
	ptr := C.gss_buffer_set_t(nil)
	min := C.OM_uint32(0)
	maj := C.wrap_gss_inquire_cred_by_oid(lib.Fp_gss_inquire_cred_by_oid,
		&min,
		cred.C_gss_cred_id_t,
		desiredObject.C_gss_OID,
		&ptr)
	err = lib.stashLastStatus(maj, min)
	if err == nil {
		dataSet = goBufferSet(ptr) // goBufferSet defined in context.go
		if nil == dataSet {
			err = ErrMallocFailed
		}
	}
	_ = lib.ReleaseBufferSet(ptr)
	return
}

// Release frees a credential.
func (cred *CredId) Release() error {
	if cred == nil || cred.C_gss_cred_id_t == nil {
		return nil
	}

	lib := cred.lib
	min := C.OM_uint32(0)
	maj := C.wrap_gss_release_cred(lib.Fp_gss_release_cred,
		&min,
		&cred.C_gss_cred_id_t)

	return lib.stashLastStatus(maj, min)
}

//TODO: Test for AddCred with existing cred

// AcquireCred implements gss_acquire_cred API, as per
// https://tools.ietf.org/html/rfc2743#page-31. outputCredHandle, actualMechs
// must be .Release()-ed by the caller
// TODO find right RFC
func (lib *Lib) AcquireCredFrom(desiredName *Name, timeReq time.Duration,
	desiredMechs *OIDSet, credUsage CredUsage, credStore KeyValueSet) (outputCredHandle *CredId,
	actualMechs *OIDSet, timeRec time.Duration, err error) {

	min := C.OM_uint32(0)
	actualMechs = lib.NewOIDSet()
	outputCredHandle = lib.NewCredId()
	timerec := C.OM_uint32(0)
	cptr := credStore.C_gss_const_key_value_set_t()
	defer Free_C_gss_const_key_value_set_t(cptr)

	maj := C.wrap_gss_acquire_cred_from(lib.Fp_gss_acquire_cred_from,
		&min,
		desiredName.C_gss_name_t,
		C.OM_uint32(timeReq.Seconds()),
		desiredMechs.C_gss_OID_set,
		C.gss_cred_usage_t(credUsage),
		cptr,
		&outputCredHandle.C_gss_cred_id_t,
		&actualMechs.C_gss_OID_set,
		&timerec)

	err = lib.stashLastStatus(maj, min)
	if err != nil {
		return nil, nil, 0, err
	}

	return outputCredHandle, actualMechs, time.Duration(timerec) * time.Second, nil
}

// AddCred implements gss_add_cred API, as per
// https://tools.ietf.org/html/rfc2743#page-36. outputCredHandle, actualMechs
// must be .Release()-ed by the caller
// TODO find right RFC
func (lib *Lib) AddCredFrom(inputCredHandle *CredId,
	desiredName *Name, desiredMech *OID, credUsage CredUsage,
	initiatorTimeReq time.Duration, acceptorTimeReq time.Duration, credStore KeyValueSet) (
	outputCredHandle *CredId, actualMechs *OIDSet,
	initiatorTimeRec time.Duration, acceptorTimeRec time.Duration,
	err error) {

	lib.Trace(fmt.Sprintf("Lib.AddCredFrom: enter"))
	defer func() {lib.Trace(fmt.Sprintf("Lib.AddCredFrom: exit"))}()
	min := C.OM_uint32(0)
	actualMechs = lib.NewOIDSet()
	outputCredHandle = lib.NewCredId()
	initSeconds := C.OM_uint32(0)
	acceptSeconds := C.OM_uint32(0)
	cptr := credStore.C_gss_const_key_value_set_t()
	defer Free_C_gss_const_key_value_set_t(cptr)

	maj := C.wrap_gss_add_cred_from(lib.Fp_gss_add_cred_from,
		&min,
		inputCredHandle.C_gss_cred_id_t,
		desiredName.C_gss_name_t,
		desiredMech.C_gss_OID,
		C.gss_cred_usage_t(credUsage),
		C.OM_uint32(initiatorTimeReq.Seconds()),
		C.OM_uint32(acceptorTimeReq.Seconds()),
		cptr,
		&outputCredHandle.C_gss_cred_id_t,
		&actualMechs.C_gss_OID_set,
		&initSeconds,
		&acceptSeconds)

	err = lib.stashLastStatus(maj, min)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	return outputCredHandle,
		actualMechs,
		time.Duration(initSeconds) * time.Second,
		time.Duration(acceptSeconds) * time.Second,
		nil
}

func (lib *Lib) StoreCred(cred *CredId, inputUsage CredUsage, desiredMech *OID,
	overwriteCred bool, defaultCred bool) (elementsStored *OIDSet,
	usageStored CredUsage, err error) {

	return cred.Store(inputUsage, desiredMech,
		overwriteCred, defaultCred)
}

func (cred *CredId) Store(inputUsage CredUsage, desiredMech *OID,
	overwriteCred bool, defaultCred bool) (elementsStored *OIDSet,
	usageStored CredUsage, err error) {

	if cred == nil || cred.C_gss_cred_id_t == nil {
		return
	}

	lib := cred.lib
	lib.Trace(fmt.Sprintf("Cred.Store: enter\n"))
	defer func() {lib.Trace(fmt.Sprintf("Cred.Store: exit\n"))}()
	min := C.OM_uint32(0)
	elementsStored = lib.NewOIDSet()
	cOverwriteCred := C.OM_uint32(0)
	if overwriteCred {
		cOverwriteCred = C.OM_uint32(1)
	}
	cDefaultCred := C.OM_uint32(0)
	if defaultCred {
		cDefaultCred = C.OM_uint32(1)
	}

	maj := C.wrap_gss_store_cred(lib.Fp_gss_store_cred,
		&min,
		cred.C_gss_cred_id_t,
		C.gss_cred_usage_t(inputUsage),
		desiredMech.C_gss_OID,
		cOverwriteCred,
		cDefaultCred,
		&(elementsStored.C_gss_OID_set),
		(*C.gss_cred_usage_t)(&usageStored))
	err = lib.stashLastStatus(maj, min)
	if err != nil {
		return nil, CredUsage(0), err
	}
	return elementsStored, usageStored, nil
}

func (lib *Lib) StoreCredInto(cred *CredId, inputCredUsage CredUsage, oid *OID,
	overwriteCred bool, defaultCred bool, credStore *KeyValueSet) (
	elementsStored *OIDSet, credUsage CredUsage, err error) {

	return cred.StoreInto(inputCredUsage, oid, overwriteCred, defaultCred, credStore)
}
func (cred *CredId) StoreInto(inputCredUsage CredUsage, oid *OID,
	overwriteCred bool, defaultCred bool, credStore *KeyValueSet) (
	elementsStored *OIDSet, credUsage CredUsage, err error) {

	if cred == nil || cred.C_gss_cred_id_t == nil {
		return
	}

	lib := cred.lib
	lib.Trace(fmt.Sprintf("Cred.StoreInto: enter\n"))
	defer func() {lib.Trace(fmt.Sprintf("Cred.StoreInto: exit\n"))}()
	cOID := C.gss_OID(nil)
	if nil != oid {
		cOID = oid.C_gss_OID
	}
	min := C.OM_uint32(0)
	kvstoreOptions := credStore.C_gss_const_key_value_set_t()
	elementsCOIDSet := C.gss_OID_set(nil)
	credUsage = CredUsage(0)
	defer Free_C_gss_const_key_value_set_t(kvstoreOptions)

	def := C.OM_uint32(0)
	if defaultCred {
		def = 1
	}
	over := C.OM_uint32(0)
	if overwriteCred {
		over = 1
	}

	maj := C.wrap_gss_store_cred_into(lib.Fp_gss_store_cred_into,
		&min,
		cred.C_gss_cred_id_t,               // input_cred_handle,
		C.gss_cred_usage_t(inputCredUsage), // input_usage,
		cOID,                               // desired_mech,
		over,
		def,
		kvstoreOptions, // cred_store,
		&elementsCOIDSet,
		(*C.gss_cred_usage_t)(&credUsage))
	if err = lib.stashLastStatus(maj, min); nil == err {
		elementsStored = lib.NewOIDSet()
		elementsStored.C_gss_OID_set = elementsCOIDSet
	}
	return
}

func (lib *Lib) ImportCred(credToken Buffer) (outputCredId *CredId,
	err error) {

	min := C.OM_uint32(0)
	outputCredId = lib.NewCredId()

	maj := C.wrap_gss_import_cred(lib.Fp_gss_import_cred,
		&min,
		credToken.C_gss_buffer_t,
		&outputCredId.C_gss_cred_id_t)

	err = lib.stashLastStatus(maj, min)
	return outputCredId, err
}

func (lib *Lib) ExportCred(inputCredHandle *CredId, credToken Buffer) (
	err error) {
	return inputCredHandle.Export(credToken)
}

func (cred *CredId) Export(credToken Buffer) (
	err error) {

	if cred == nil || cred.C_gss_cred_id_t == nil {
		return
	}

	lib := cred.lib
	min := C.OM_uint32(0)
	maj := C.wrap_gss_export_cred(lib.Fp_gss_export_cred,
		&min,
		cred.C_gss_cred_id_t,
		credToken.C_gss_buffer_t)

	err = lib.stashLastStatus(maj, min)
	return err
}

func (lib *Lib) AcquireCredWithPassword(desiredName *Name, password *Buffer,
	timeReq time.Duration, desiredMechs *OIDSet, credUsage CredUsage) (
	outputCredHandle *CredId, actualMechs *OIDSet, timeRec time.Duration,
	err error) {

	outputCredHandle = lib.NewCredId()
	actualMechs = lib.NewOIDSet()
	dur := C.OM_uint32(0)
	min := C.OM_uint32(0)

	maj := C.wrap_gss_acquire_cred_with_password(lib.Fp_gss_acquire_cred_with_password,
		&min,
		desiredName.C_gss_name_t,
		password.C_gss_buffer_t,
		C.OM_uint32(timeReq.Seconds()),
		desiredMechs.C_gss_OID_set,
		C.gss_cred_usage_t(credUsage),
		&outputCredHandle.C_gss_cred_id_t,
		&actualMechs.C_gss_OID_set,
		&dur)
	timeRec = time.Duration(dur) * time.Second
	err = lib.stashLastStatus(maj, min)
	if err != nil {
		return nil, nil, time.Duration(0) * time.Second, err
	}
	return outputCredHandle, actualMechs, timeRec, err
}

func (lib *Lib) AddCredWithPassword(inputCredHandle *CredId, desiredName *Name,
	desiredMech *OID, password *Buffer, credUsage CredUsage,
	initiatorTimeReq time.Duration, acceptorTimeReq time.Duration) (
	outputCredHandle *CredId, actualMechs *OIDSet, initiatorTimeRec time.Duration,
	acceptorTimeRec time.Duration, err error) {

	outputCredHandle = lib.NewCredId()
	actualMechs = lib.NewOIDSet()
	initdur := C.OM_uint32(0)
	accedur := C.OM_uint32(0)
	min := C.OM_uint32(0)

	maj := C.wrap_gss_add_cred_with_password(lib.Fp_gss_add_cred_with_password,
		&min,
		inputCredHandle.C_gss_cred_id_t,
		desiredName.C_gss_name_t,
		desiredMech.C_gss_OID,
		password.C_gss_buffer_t,
		C.gss_cred_usage_t(credUsage),
		C.OM_uint32(initiatorTimeReq.Seconds()),
		C.OM_uint32(acceptorTimeReq.Seconds()),
		&outputCredHandle.C_gss_cred_id_t,
		&actualMechs.C_gss_OID_set,
		&initdur,
		&accedur)
	initiatorTimeRec = time.Duration(initdur) * time.Second
	acceptorTimeRec = time.Duration(accedur) * time.Second
	err = lib.stashLastStatus(maj, min)
	if err != nil {
		return nil, nil, 0 * time.Second, 0 * time.Second, err
	}
	return outputCredHandle, actualMechs, initiatorTimeRec, acceptorTimeRec, err
}

// before calling this function, service/username need to be connonicalized, and imported into gssapi library.
func (lib *Lib) AcquireCredWithKinit(desiredName *Name, ktName string, timeReq time.Duration,
	desiredMechs *OIDSet, credUsage CredUsage, flags kinitOptionFlags) (outputCredHandle *CredId,
	actualMechs *OIDSet, timeRec time.Duration, err error) {

	lib.Debug(fmt.Sprintf("In AcquireCredWithKinit()")) // print at opposite severity levels

	if credUsage == GSS_C_INITIATE || credUsage == GSS_C_BOTH {
		//KINIT so that we can acquire creds for "GSS_C_BOTH" or "GSS_C_INITIATE" usages
		// here be low level krb5 library calls, do not export these.
		if _, err := lib.Kinit(desiredName, ktName, timeReq, desiredMechs, credUsage, flags); err != nil {
			return nil, nil, 0 * time.Second, err
		}
	}
	return lib.AcquireCred(desiredName, timeReq, desiredMechs, credUsage)
}
