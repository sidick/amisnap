/* no_locale.c -- defeat libnix's auto-open of locale.library.
 *
 * libamisslstubs.a (AmiSSL's vendored, precompiled call-stub library --
 * see the m68k build rule's own comment in the Makefile) carries an
 * unresolved reference to `LocaleBase`. Left unresolved, GNU ld pulls
 * the matching glue object out of libnix's own libstubs.a to satisfy
 * it -- and that glue object does two things at once: it defines the
 * pointer AND registers it in libnix's __LIB_LIST__ set element, which
 * makes __initlibraries() open locale.library unconditionally at
 * program startup and abort the whole program (RC 20, before main()
 * ever runs -- confirmed live: "locale.library failed to load" on a
 * Copperline boot with no locale.library staged) if that open fails.
 *
 * locale.library is a Workbench-disk resident module, not a ROM
 * component, and AmiSnap's floor is a plain AmigaDOS boot (RKRM/libnix
 * docs: code that actually depends on locale.library is written to
 * degrade to "C" behaviour when its base is NULL, exactly like running
 * with no locale.library present at all). Providing our own,
 * ordinary-object-file definition here -- linked before libstubs.a per
 * the documented link order -- satisfies amisslstubs.a's reference
 * directly, so ld never pulls in libnix's auto-open glue for this
 * library, and LocaleBase simply stays NULL: the same state a real
 * "no locale.library installed" system would leave it in, not a crash.
 */
#include <exec/types.h>
#include <exec/libraries.h>

struct Library *LocaleBase = NULL;
