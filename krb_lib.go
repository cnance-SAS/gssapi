// +build darwin linux freebsd

package gssapi

/*
#include <gssapi/gssapi.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <krb5.h>

krb5_error_code
wrap_krb5_init_context(void *fp,
	krb5_context *ctx)
{
	return ((krb5_error_code(*)(
		krb5_context *)
	) fp) (
		ctx
	);
}

void
wrap_krb5_free_context(void *fp,
	krb5_context ctx)
{
	return ((void(*)(
		krb5_context)
	) fp) (
		ctx
	);
}

krb5_error_code
wrap_krb5_parse_name(void *fp,
	krb5_context ctx,
	const char * name,
	krb5_principal *k5Me)
{
	return ((krb5_error_code(*) (
		krb5_context,
		const char *,
		krb5_principal *)
	) fp) (
		ctx,
		name,
		k5Me
	);
}

void
wrap_krb5_free_principal (void *fp,
	krb5_context ctx,
	krb5_principal val)
{
	return ((void(*) (
		krb5_context,
		krb5_principal)
	) fp) (
		ctx,
		val
	);
}

const char *
wrap_krb5_cc_default_name (void *fp,
	krb5_context ctx)
{
	return ((const char *(*) (
		krb5_context)
	) fp) (
		ctx
	);
}

const char *
wrap_krb5_cc_get_name (void *fp,
	krb5_context ctx,
	krb5_ccache cache)
{
	return ((const char *(*) (
		krb5_context,
		krb5_ccache)
	) fp) (
		ctx,
		cache
	);
}

krb5_error_code
wrap_krb5_cc_get_principal (void *fp,
	krb5_context ctx,
	krb5_ccache cache,
	krb5_principal * principal)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_ccache,
		krb5_principal *)
	) fp) (
		ctx,
		cache,
		principal
	);
}

krb5_error_code
wrap_krb5_cc_initialize (void *fp,
	krb5_context ctx,
	krb5_ccache cache,
	krb5_principal principal)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_ccache,
		krb5_principal)
	) fp) (
		ctx,
		cache,
		principal
	);
}

krb5_error_code
wrap_krb5_cc_new_unique (void *fp,
	krb5_context ctx,
	const char *type,
	const char *hint,
	krb5_ccache *cache
	)
{
	return ((krb5_error_code(*) (
		krb5_context,
		const char *,
		const char *,
		krb5_ccache *
		)
	) fp) (
		ctx,
		type,
		hint,
		cache
	);
}

krb5_error_code
wrap_krb5_cc_resolve (void *fp,
	krb5_context ctx,
	char *name,
	krb5_ccache *cache)
{
	return ((krb5_error_code(*) (
		krb5_context,
		char *,
		krb5_ccache *)
	) fp) (
		ctx,
		name,
		cache
	);
}

krb5_error_code
wrap_krb5_cc_destroy (void *fp,
	krb5_context ctx,
	krb5_ccache cache)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_ccache)
	) fp) (
		ctx,
		cache
	);
}

krb5_error_code
wrap_krb5_get_init_creds_keytab (void *fp,
	krb5_context ctx,
	krb5_creds *creds,
	krb5_principal client,
	krb5_keytab arg_keytab,
	krb5_deltat start_time,
	const char *in_tkt_service,
	krb5_get_init_creds_opt *k5_gic_options)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_creds *,
		krb5_principal,
		krb5_keytab,
		krb5_deltat,
		const char *,
		krb5_get_init_creds_opt *)
	) fp) (
		ctx,
		creds,
		client,
		arg_keytab,
		start_time,
		in_tkt_service,
		k5_gic_options
	);
}

krb5_error_code
wrap_krb5_get_init_creds_opt_alloc (void *fp,
	krb5_context ctx,
	krb5_get_init_creds_opt **opt)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_get_init_creds_opt **)
	) fp) (
		ctx,
		opt
	);
}

void
wrap_krb5_get_init_creds_opt_free (void *fp,
	krb5_context ctx,
	krb5_get_init_creds_opt *opt)
{
	return ((void(*) (
		krb5_context,
		krb5_get_init_creds_opt *)
	) fp) (
		ctx,
		opt
	);
}

krb5_error_code
wrap_krb5_get_init_creds_opt_set_out_ccache (void *fp,
	krb5_context ctx,
	krb5_get_init_creds_opt *opt,
	krb5_ccache cache)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_get_init_creds_opt *,
		krb5_ccache)
	) fp) (
		ctx,
		opt,
		cache
	);
}

krb5_error_code
wrap_krb5_kt_close (void *fp,
	krb5_context ctx,
	krb5_keytab keytab)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_keytab
		)
	) fp) (
		ctx,
		keytab
	);
}

krb5_error_code
wrap_krb5_kt_default (void *fp,
	krb5_context ctx,
	krb5_keytab *ktid)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_keytab *)
	) fp) (
		ctx,
		ktid
	);
}

krb5_error_code
wrap_krb5_kt_resolve (void *fp,
	krb5_context ctx,
	const char *name,
	krb5_keytab *ktid)
{
	return ((krb5_error_code(*) (
		krb5_context,
		const char *,
		krb5_keytab *)
	) fp) (
		ctx,
		name,
		ktid
	);
}

krb5_error_code
wrap_krb5_unparse_name (void *fp,
	krb5_context ctx,
	krb5_principal principal,
	char ** name)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_principal,
		char **)
	) fp) (
		ctx,
		principal,
		name
	);
}

void
wrap_krb5_free_unparsed_name (void *fp,
	krb5_context ctx,
	char *val)
{
	return ((void(*) (
		krb5_context,
		char *)
	) fp ) (
		ctx,
		val
	);
}

void
wrap_krb5_get_init_creds_opt_set_forwardable(void *fp,
	krb5_get_init_creds_opt * opt,
	int forwardable)
{
	return ((void(*) (
		krb5_get_init_creds_opt *,
		int)
	) fp ) (
		opt,
		forwardable
	);
}

krb5_error_code
wrap_krb5_verify_init_creds(void * fp,
	krb5_context context,
	krb5_creds * creds,
	krb5_principal server,
	krb5_keytab keytab,
	krb5_ccache * ccache,
	krb5_verify_init_creds_opt * options)
{
	return ((krb5_error_code(*) (
		krb5_context,
		krb5_creds *,
		krb5_principal,
		krb5_keytab,
		krb5_ccache *,
		krb5_verify_init_creds_opt *)
	) fp) (
		context,
		creds,
		server,
		keytab,
		ccache,
		options
	);
}

void
wrap_krb5_free_cred_contents(void * fp,
	krb5_context context,
	krb5_creds *val)
{
	return ((void(*) (
		krb5_context,
		krb5_creds *creds)
	) fp) (
		context,
		val
	);
}

void
wrap_krb5_get_init_creds_opt_set_address_list (void *fp,
	krb5_get_init_creds_opt * opt,
	krb5_address ** addresses)
{
	return ((void(*)(
		krb5_get_init_creds_opt *,
		krb5_address **)
	) fp) (
		opt,
		addresses
	);
}

void
wrap_krb5_get_init_creds_opt_set_proxiable(void *fp,
	krb5_get_init_creds_opt * opt,
	int proxiable)
{
	return ((void(*) (
		krb5_get_init_creds_opt *,
		int)
	) fp ) (
		opt,
		proxiable
	);
}

krb5_error_code
wrap_krb5_kt_default_name(void *fp,
	krb5_context context,
	char * name,
	int name_size)
{
	return ((krb5_error_code(*) (
		krb5_context,
		char *,
		int)
	) fp) (
		context,
		name,
		name_size
	);
}

const char *
wrap_krb5_get_error_message(void* fp,
	krb5_context ctx,
	krb5_error_code code)
{
	return ((const char *(*) (
		krb5_context,
		krb5_error_code)
	) fp) (
		ctx,
		code
	);
}

void
wrap_krb5_free_error_message(void *fp,
	krb5_context ctx,
	const char * msg)
{
	return ((void(*) (
		krb5_context,
		const char *)
	) fp) (
		ctx,
		msg
	);
}

*/
import "C"

import (
	"fmt"
	"time"
	"unsafe"
)

func loadFunc(handle unsafe.Pointer, name string) (fp unsafe.Pointer, err error) {
	err = nil
	cfname := C.CString(name)
	fp = C.dlsym(handle, cfname)
	C.free(unsafe.Pointer(cfname))
	if fp == nil {
		err = fmt.Errorf("%s", C.GoString(C.dlerror()))
	}
	return fp, err
}

func (k5 *krbFtable) krbPopulateFunctions(handle unsafe.Pointer) (err error) {
	if k5.fp_krb5_init_context, err = loadFunc(handle, "krb5_init_context"); err != nil {
		return err
	}
	if k5.fp_krb5_free_context, err = loadFunc(handle, "krb5_free_context"); err != nil {
		return err
	}
	if k5.fp_krb5_parse_name, err = loadFunc(handle, "krb5_parse_name"); err != nil {
		return err
	}
	if k5.fp_krb5_free_principal, err = loadFunc(handle, "krb5_free_principal"); err != nil {
		return err
	}
	if k5.fp_krb5_kt_resolve, err = loadFunc(handle, "krb5_kt_resolve"); err != nil {
		return err
	}
	if k5.fp_krb5_kt_default, err = loadFunc(handle, "krb5_kt_default"); err != nil {
		return err
	}
	if k5.fp_krb5_kt_close, err = loadFunc(handle, "krb5_kt_close"); err != nil {
		return err
	}
	if k5.fp_krb5_cc_default_name, err = loadFunc(handle, "krb5_cc_default_name"); err != nil {
		return err
	}
	if k5.fp_krb5_cc_resolve, err = loadFunc(handle, "krb5_cc_resolve"); err != nil {
		return err
	}
	if k5.fp_krb5_cc_new_unique, err = loadFunc(handle, "krb5_cc_new_unique"); err != nil {
		return err
	}
	if k5.fp_krb5_cc_get_name, err = loadFunc(handle, "krb5_cc_get_name"); err != nil {
		return err
	}
	if k5.fp_krb5_cc_initialize, err = loadFunc(handle, "krb5_cc_initialize"); err != nil {
		return err
	}
	if k5.fp_krb5_cc_destroy, err = loadFunc(handle, "krb5_cc_destroy"); err != nil {
		return err
	}
	if k5.fp_krb5_cc_get_principal, err = loadFunc(handle, "krb5_cc_get_principal"); err != nil {
		return err
	}
	if k5.fp_krb5_unparse_name, err = loadFunc(handle, "krb5_unparse_name"); err != nil {
		return err
	}
	if k5.fp_krb5_free_unparsed_name, err = loadFunc(handle, "krb5_free_unparsed_name"); err != nil {
		return err
	}
	if k5.fp_krb5_get_init_creds_opt_alloc, err = loadFunc(handle, "krb5_get_init_creds_opt_alloc"); err != nil {
		return err
	}
	if k5.fp_krb5_get_init_creds_opt_free, err = loadFunc(handle, "krb5_get_init_creds_opt_free"); err != nil {
		return err
	}
	if k5.fp_krb5_get_init_creds_opt_set_out_ccache, err = loadFunc(handle, "krb5_get_init_creds_opt_set_out_ccache"); err != nil {
		return err
	}
	if k5.fp_krb5_get_init_creds_opt_set_forwardable, err = loadFunc(handle, "krb5_get_init_creds_opt_set_forwardable"); err != nil {
		return err
	}
	if k5.fp_krb5_verify_init_creds, err = loadFunc(handle, "krb5_verify_init_creds"); err != nil {
		return err
	}
	if k5.fp_krb5_free_cred_contents, err = loadFunc(handle, "krb5_free_cred_contents"); err != nil {
		return err
	}
	if k5.fp_krb5_get_init_creds_opt_set_address_list, err = loadFunc(handle, "krb5_get_init_creds_opt_set_address_list"); err != nil {
		return err
	}
	if k5.fp_krb5_get_init_creds_opt_set_proxiable, err = loadFunc(handle, "krb5_get_init_creds_opt_set_proxiable"); err != nil {
		return err
	}
	if k5.fp_krb5_get_init_creds_keytab, err = loadFunc(handle, "krb5_get_init_creds_keytab"); err != nil {
		return err
	}
	if k5.fp_krb5_kt_default_name, err = loadFunc(handle, "krb5_kt_default_name"); err != nil {
		return err
	}
	if k5.fp_krb5_free_error_message, err = loadFunc(handle, "krb5_free_error_message"); err != nil {
		return err
	}
	if k5.fp_krb5_get_error_message, err = loadFunc(handle, "krb5_get_error_message"); err != nil {
		return err
	}
	return err
}

type krbFtable struct {
	ctx                                         C.krb5_context
	fp_krb5_init_context                        unsafe.Pointer
	fp_krb5_free_context                        unsafe.Pointer
	fp_krb5_parse_name                          unsafe.Pointer
	fp_krb5_free_principal                      unsafe.Pointer
	fp_krb5_kt_resolve                          unsafe.Pointer
	fp_krb5_kt_default                          unsafe.Pointer
	fp_krb5_kt_close                            unsafe.Pointer
	fp_krb5_cc_default_name                     unsafe.Pointer
	fp_krb5_cc_resolve                          unsafe.Pointer
	fp_krb5_cc_new_unique                       unsafe.Pointer
	fp_krb5_cc_get_name                         unsafe.Pointer
	fp_krb5_cc_initialize                       unsafe.Pointer
	fp_krb5_cc_destroy                          unsafe.Pointer
	fp_krb5_cc_get_principal                    unsafe.Pointer
	fp_krb5_unparse_name                        unsafe.Pointer
	fp_krb5_free_unparsed_name                  unsafe.Pointer
	fp_krb5_get_init_creds_opt_alloc            unsafe.Pointer
	fp_krb5_get_init_creds_opt_free             unsafe.Pointer
	fp_krb5_get_init_creds_opt_set_out_ccache   unsafe.Pointer
	fp_krb5_get_init_creds_opt_set_forwardable  unsafe.Pointer
	fp_krb5_verify_init_creds                   unsafe.Pointer
	fp_krb5_free_cred_contents                  unsafe.Pointer
	fp_krb5_get_init_creds_opt_set_address_list unsafe.Pointer
	fp_krb5_get_init_creds_opt_set_proxiable    unsafe.Pointer
	fp_krb5_get_init_creds_keytab               unsafe.Pointer
	fp_krb5_kt_default_name                     unsafe.Pointer
	fp_krb5_get_error_message                   unsafe.Pointer
	fp_krb5_free_error_message                  unsafe.Pointer
}

func (k5 *krbFtable) Load(handle unsafe.Pointer) error {
	err := k5.krbPopulateFunctions(handle)
	if err != nil {
		return err
	}
	ov := k5.ctx
	err = k5.initContext()
	if err != nil {
		return err
	}
	if k5.ctx == ov {
		return fmt.Errorf("krb5 context not created")
	}
	return nil
}

func (k5 *krbFtable) Unload() {
	// causes seg fault, because function pointer is to bad address??? k5.freeContext()
}

func (lib *Lib) Kinit(desiredName *Name, ktName string, timeReq time.Duration,
	desiredMechs *OIDSet, credUsage CredUsage, flags kinitOptionFlags) (cred C.krb5_ccache, err error) {

	// try to Kinit with desired name (might be nil), nil might still work, so try
	cred, err = lib.krb.Kinit(desiredName, ktName, timeReq, desiredMechs, credUsage, flags)
	if err != nil {
		lib.Debug(fmt.Sprintf("gssapilib.Lib.Kinit: first kinit returned err: %v\n  ", err))
		if desiredName == nil || desiredName.C_gss_name_t == nil {
			lib.Debug("gssapilib.Lib.Kinit: and desired name is nil\n")
			// Kinit failed, and desired name is nil,
			// Find default SPN from keytab
			tCred, mechs, _, err1 := lib.AcquireCred(desiredName, timeReq, desiredMechs, GSS_C_ACCEPT)
			err = err1
			if err == nil {
				defer func() {_ = tCred.Release()}()
				_ = mechs.Release()
				defaultSPN, _, _, oidSet, err1 := lib.InquireCred(tCred)
				err = err1
				if err == nil {
					_ = oidSet.Release()
					lib.Debug(fmt.Sprintf("gssapilib.Lib.Kinit: Found principal %s in keytab\n", defaultSPN.String()))
					defer func() { _ = defaultSPN.Release() }()
					cred, err = lib.krb.Kinit(defaultSPN, ktName, timeReq, desiredMechs, credUsage, flags)
					if err != nil {
						lib.Debug(fmt.Sprintf("gssapi.Lib.Kinit: second Kinit error=\n%s\n", err.Error()))
					} else {
						lib.Debug("gssapi.lib.Kinit: second Kinit succeeded\n")
					}
				} else {
					lib.Debug("gssapilib.Lib.Kinit: Error InquireCred to infer principal name.\n")
					return nil, err //TODO:  This is an error case.
				}
			} else {
				lib.Debug("gssapilib.Lib.Kinit: Failed to AcquireCred in order to find SPN.\n")
				return nil, err // todo: this is an error case.
			}
		} else {
			lib.Debug(fmt.Sprintf("Failed to Kinit for %s\n", desiredName.String()))
		}
	}

	return cred, err
}

// global error, so caller can handle this case.
var ErrKinitNeedPrincipal = fmt.Errorf("kinit failed, Principal not supplied")

type kinitOptionFlags int
const (
	KinitDefaults       kinitOptionFlags = 0
	KinitForwardable    kinitOptionFlags = 1<<0
	KinitNotForwardable kinitOptionFlags = 1<<1
	KinitProxiable      kinitOptionFlags = 1<<2
	KinitNotProxiable   kinitOptionFlags = 1<<3
)

func (k5 krbFtable) Kinit(desiredName *Name, ktName string, timeReq time.Duration,
	desiredMechs *OIDSet, credUsage CredUsage, flags kinitOptionFlags) (ccache C.krb5_ccache, err error) {

	var k5Me C.krb5_principal = nil
	if desiredName != nil && desiredName.C_gss_name_t != nil {
		name := desiredName.String()
		if k5Me, err = k5.parseName(name); err != nil {
			return nil, err
			// todo error
		}
		defer func() {
			k5.freePrincipal(k5Me)
		}()
	} else {
		//error maybe
	}

	var keytab C.krb5_keytab
	if ktName != "" {
		if keytab, err = k5.ktResolve(ktName); err != nil {
			return nil, fmt.Errorf("Lib.krb5.Kinit: Error while resolving keytab: %s\n", ktName)
		}
	} else {
		if keytab, err = k5.ktDefault(); err != nil {
			return nil, err
		}
	}
	defer func() { _ = k5.ktClose(keytab) }()

	k5OutCacheName := k5.ccDefaultName()
	// k5Ctx cleans up the default Name
	var k5OutCc C.krb5_ccache
	k5OutCc, err = k5.ccResolve(k5OutCacheName)
	if err != nil { // ccResolve failure
		if k5Me != nil { // but I have principal name from user
			// initialize ccache
			if k5OutCc, err = k5.ccNewUnique("FILE", ""); err != nil {
				return nil, err
			} else {
				// getName is just for debugging
				k5OutCacheName = k5.ccGetName(k5OutCc)
				if err = k5.ccInitialize(k5OutCc, k5Me); err != nil {
					_ = k5.ccDestroy(k5OutCc)
					return nil, err
				}
			}
		} else { // no principal name
			// This triggers Lib.Kinit to open default keytab and gather principal name from there.
			return nil, ErrKinitNeedPrincipal
		}
	} else { // happy resolving cache: may or may not have principal.
		var p2 C.krb5_principal
		if p2, err = k5.ccGetPrincipal(k5OutCc); err == nil {
			defer func() { k5.freePrincipal(p2) }()
		}
		if k5Me == nil && p2 != nil {
			k5Me = p2
		} else if k5Me == nil {
			// This triggers Lib.Kinit to open default keytab and gather principal name from there.
			return nil, ErrKinitNeedPrincipal
		}
	}

	var options *C.krb5_get_init_creds_opt
	if options, err = k5.getInitCredsOptAlloc(); err != nil {
		_ = k5.ccDestroy(k5OutCc)
		return nil, err
	}
	defer func() {
		k5.getInitCredsOptFree(options)
	}()

	if err = k5.getInitCredsOptSetOutCcache(options, k5OutCc); err != nil {
		return nil, err
	}
	//krb5_get_init_creds_opt_set_tkt_life(options, opts->lifetime);
	//krb5_get_init_creds_opt_set_renew_life(options, opts->rlife);

	// There is an option to just not set forwardable/proxiable at all
	if flags &KinitForwardable == KinitForwardable {
		k5.getInitCredsOptSetForwardable(options, 1)
	}
	if flags &KinitNotForwardable == KinitNotForwardable { // not overrides do
		k5.getInitCredsOptSetForwardable(options, 0)
	}
	if flags &KinitProxiable == KinitProxiable {
		k5.getInitCredsOptSetProxiable(options, 1)
	}
	if flags &KinitNotProxiable == KinitNotProxiable { // not overrides do
		k5.getInitCredsOptSetProxiable(options, 0)
	}
	//krb5_get_init_creds_opt_set_canonicalize(options, 1);
	//krb5_get_init_creds_opt_set_anonymous(options, 1);
	k5.getInitCredsOptSetAddressList(options, nil)
	// armor ccache?
	//krb5_get_init_creds_opt_set_fast_ccache_name(k5->ctx, options,
	//                                                     opts->armor_ccache)
	//krb5_get_init_creds_opt_set_pac_request(k5->ctx, options, TRUE);
	//for (i = 0; i < opts->num_pa_opts; i++) {
	//    ret = krb5_get_init_creds_opt_set_pa(k5->ctx, options,
	//                                         opts->pa_opts[i].attr,
	//                                         opts->pa_opts[i].value);
	//    if (ret) {
	//        com_err(progname, ret, _("while setting '%s'='%s'"),
	//                opts->pa_opts[i].attr, opts->pa_opts[i].value);
	//        goto cleanup;
	//    }
	//    if (opts->verbose) {
	//        fprintf(stderr, _("PA Option %s = %s\n"), opts->pa_opts[i].attr,
	//                opts->pa_opts[i].value);
	//    }
	//}

	// Get the creds
	var myCred C.krb5_creds
	myCred, err = k5.getInitCredsKeytab(k5Me, keytab,
		time.Duration(0), "", options)
	if nil != err {
		_ = k5.ccDestroy(k5OutCc)
		return nil, err
	}
	defer k5.freeCredContents(&myCred)
	// Verify the cred, todo: needed?
	err = k5.verifyInitCreds(&myCred, nil, nil, nil, nil)
	if err != nil {
		defer func() { _ = k5.ccDestroy(k5OutCc) }()
		return nil, err
	}
	// store the cred, I set the option above, so this should happen already
	//C.krb5_cc_store_cred(k5Ctx, k5OutCc, &myCred)
	return k5OutCc, err
}

func (k5 *krbFtable) initContext() error {
	ret := C.wrap_krb5_init_context(k5.fp_krb5_init_context, &(k5.ctx))
	if 0 != ret {
		return fmt.Errorf("Failed to init krb library\n\t%s", k5.getErrorMessage(ret).Error())
	}
	return nil
}

func (k5 *krbFtable) freeContext() {
	if k5.ctx != nil {
		C.wrap_krb5_free_context(k5.fp_krb5_free_context, k5.ctx)
		k5.ctx = nil
	}
}

func (k5 krbFtable) parseName(name string) (principal C.krb5_principal, err error) {
	cstr := C.CString(name)
	defer C.free(unsafe.Pointer(cstr))
	err = nil
	ret := C.wrap_krb5_parse_name(k5.fp_krb5_parse_name,
		k5.ctx,
		cstr,
		&principal)
	if ret != 0 {
		err = k5.getErrorMessage(ret)
	}
	return principal, err
}

func (k5 krbFtable) freePrincipal(principal C.krb5_principal) {
	if nil != principal {
		C.wrap_krb5_free_principal(k5.fp_krb5_free_principal,
			k5.ctx,
			principal,
		)
	}
}

func (k5 krbFtable) ktResolve(Name string) (keytab C.krb5_keytab, err error) {
	ktName := C.CString(Name)
	defer C.free(unsafe.Pointer(ktName))
	ret := C.wrap_krb5_kt_resolve(k5.fp_krb5_kt_resolve,
		k5.ctx,
		ktName,
		&keytab)
	if 0 != ret {
		err = k5.getErrorMessage(ret)
	}
	return keytab, err
}

func (k5 krbFtable) ktDefault() (keytab C.krb5_keytab, err error) {
	ret := C.wrap_krb5_kt_default(k5.fp_krb5_kt_default,
		k5.ctx,
		&keytab)
	if 0 != ret {
		err = k5.getErrorMessage(ret)
	}
	return keytab, err
}

func (k5 krbFtable) ktClose(keytab C.krb5_keytab) (err error) {
	if keytab != nil {
		ret := C.wrap_krb5_kt_close(k5.fp_krb5_kt_close,
			k5.ctx,
			keytab)
		if 0 != ret {
			err = k5.getErrorMessage(ret)
		}
	}
	return err
}

func (k5 krbFtable) ccDefaultName() string {
	// k5.ctx retains ownership of cstr's memory, we don't need to clean it up.
	cstr := C.wrap_krb5_cc_default_name(k5.fp_krb5_cc_default_name,
		k5.ctx)
	return C.GoString(cstr)
}

func (k5 krbFtable) ccResolve(s string) (cache C.krb5_ccache, err error) {
	cstr := C.CString(s)
	defer C.free(unsafe.Pointer(cstr))
	ret := C.wrap_krb5_cc_resolve(k5.fp_krb5_cc_resolve,
		k5.ctx,
		cstr,
		&cache)
	if 0 != ret {
		err = k5.getErrorMessage(ret)
	}
	return cache, err
}

func (k5 krbFtable) ccNewUnique(tpe string, hint string) (cache C.krb5_ccache, err error) {
	tCstr := C.CString(tpe)
	hCstr := C.CString(hint)
	defer C.free(unsafe.Pointer(tCstr))
	defer C.free(unsafe.Pointer(hCstr))

	ret := C.wrap_krb5_cc_new_unique(k5.fp_krb5_cc_new_unique,
		k5.ctx,
		tCstr,
		hCstr,
		&cache)
	if 0 != ret {
		err = k5.getErrorMessage(ret)
	}
	return cache, err
}

func (k5 *krbFtable) ccDestroy(cache C.krb5_ccache) error {
	if nil != cache {
		ret := C.wrap_krb5_cc_destroy(k5.fp_krb5_cc_destroy,
			k5.ctx,
			cache)
		if 0 != ret {
			return k5.getErrorMessage(ret)
		}
	}
	return nil
}

func (k5 krbFtable) ccInitialize(ccache C.krb5_ccache, principal C.krb5_principal) (err error) {
	ret := C.wrap_krb5_cc_initialize(k5.fp_krb5_cc_initialize,
		k5.ctx,
		ccache,
		principal)
	if 0 != ret {
		err = k5.getErrorMessage(ret)
	}
	return err
}

func (k5 krbFtable) ccGetName(ccache C.krb5_ccache) string {
	// ccache retains ownership of cstr's memory, we do not need to clean up.
	cstr := C.wrap_krb5_cc_get_name(k5.fp_krb5_cc_get_name,
		k5.ctx,
		ccache)
	return C.GoString(cstr)
}

// caller must use k5.freePrincipal() when finished with principal.
func (k5 krbFtable) ccGetPrincipal(ccache C.krb5_ccache) (principal C.krb5_principal, err error) {
	ret := C.wrap_krb5_cc_get_principal(k5.fp_krb5_cc_get_principal,
		k5.ctx,
		ccache,
		&principal)
	if 0 != ret {
		err = k5.getErrorMessage(ret)
	}
	return principal, err
}

func (k5 krbFtable) unparseName(principal C.krb5_principal) (name string, err error) {
	var cstr *C.char
	ret := C.wrap_krb5_unparse_name(k5.fp_krb5_unparse_name,
		k5.ctx,
		principal,
		&cstr)
	if 0 != ret {
		return "", k5.getErrorMessage(ret)
	}
	name = C.GoString(cstr)
	C.wrap_krb5_free_unparsed_name(k5.fp_krb5_free_unparsed_name,
		k5.ctx,
		cstr)
	return name, nil
}

func (k5 krbFtable) getInitCredsOptAlloc() (opt *C.krb5_get_init_creds_opt, err error) {
	ret := C.wrap_krb5_get_init_creds_opt_alloc(k5.fp_krb5_get_init_creds_opt_alloc,
		k5.ctx,
		&opt)
	if 0 != ret {
		err = k5.getErrorMessage(ret)
	}
	return opt, err
}

func (k5 krbFtable) getInitCredsOptSetOutCcache(opt *C.krb5_get_init_creds_opt, ccache C.krb5_ccache) error {
	ret := C.wrap_krb5_get_init_creds_opt_set_out_ccache(k5.fp_krb5_get_init_creds_opt_set_out_ccache,
		k5.ctx,
		opt,
		ccache)
	if 0 != ret {
		return k5.getErrorMessage(ret)
	}
	return nil
}

func (k5 krbFtable) getInitCredsOptSetForwardable(opt *C.krb5_get_init_creds_opt, i int) {
	if 0 != i {
		i = 1
	}
	C.wrap_krb5_get_init_creds_opt_set_forwardable(k5.fp_krb5_get_init_creds_opt_set_forwardable,
		opt,
		C.int(i))
}

func (k5 krbFtable) getInitCredsOptSetProxiable(opt *C.krb5_get_init_creds_opt, i int) {
	if 0 != i {
		i = 1
	}
	C.wrap_krb5_get_init_creds_opt_set_forwardable(k5.fp_krb5_get_init_creds_opt_set_proxiable,
		opt,
		C.int(i))
}

func (k5 krbFtable) getInitCredsOptSetAddressList(opt *C.krb5_get_init_creds_opt, addresses **C.krb5_address) {
	C.wrap_krb5_get_init_creds_opt_set_address_list(k5.fp_krb5_get_init_creds_opt_set_address_list,
		opt,
		addresses,
	)
}

func (k5 krbFtable) getInitCredsKeytab(principal C.krb5_principal,
	keytab C.krb5_keytab,
	startAt time.Duration,
	inTktService string,
	opt *C.krb5_get_init_creds_opt) (creds C.krb5_creds, err error) {

	at := C.int(startAt.Nanoseconds() >> 32)
	cstr := C.CString(inTktService)
	defer C.free(unsafe.Pointer(cstr))
	if inTktService == "" {
		cstr = nil
	}
	ret := C.wrap_krb5_get_init_creds_keytab(k5.fp_krb5_get_init_creds_keytab,
		k5.ctx,
		&creds,
		principal,
		keytab,
		at,
		cstr,
		opt)
	if 0 != ret {
		return C.krb5_creds{}, k5.getErrorMessage(ret)
	}
	return creds, nil
}

func (k5 krbFtable) freeCredContents(creds *C.krb5_creds) {
	if nil != creds {
		C.wrap_krb5_free_cred_contents(k5.fp_krb5_free_cred_contents,
			k5.ctx,
			creds)
	}
}

func (k5 krbFtable) verifyInitCreds(creds *C.krb5_creds, server C.krb5_principal, keytab C.krb5_keytab, ccache *C.krb5_ccache, options *C.krb5_verify_init_creds_opt) error {
	ret := C.wrap_krb5_verify_init_creds(k5.fp_krb5_verify_init_creds,
		k5.ctx,
		creds,
		server,
		keytab,
		ccache,
		options,
	)
	if 0 != ret {
		return k5.getErrorMessage(ret)
	}
	return nil
}

func (k5 krbFtable) ktDefaultName() (string, error) {
	cstr := C.malloc(1024)
	if cstr == nil {
		return "", ErrMallocFailed
	}
	defer C.free(cstr)
	ret := C.wrap_krb5_kt_default_name(k5.fp_krb5_kt_default_name,
		k5.ctx,
		(*C.char)(cstr),
		1024)
	if ret != 0 {
		return "", k5.getErrorMessage(ret)
	}
	name := C.GoString((*C.char)(cstr))
	return name, nil
}

func (k5 krbFtable) getErrorMessage(errorCode C.krb5_error_code) error {
	cstr := C.wrap_krb5_get_error_message(k5.fp_krb5_get_error_message,
		k5.ctx,
		errorCode)
	defer C.wrap_krb5_free_error_message(k5.fp_krb5_free_error_message,
		k5.ctx,
		cstr)
	return fmt.Errorf("%s", C.GoString(cstr))
}

func (k5 *krbFtable) getInitCredsOptFree(opt *C.krb5_get_init_creds_opt) {
	if nil != opt {
		C.wrap_krb5_get_init_creds_opt_free(k5.fp_krb5_get_init_creds_opt_free,
			k5.ctx,
			opt)
	}
}
