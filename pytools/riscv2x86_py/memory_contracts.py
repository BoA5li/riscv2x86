"""Finite memory instruction contracts with distinct access/carrier roles."""
LOAD_ROLES = {}
for address in ('gpr-address', 'gpr-address-disp32'):
    for access in (8,16,32,64):
        LOAD_ROLES[f'x86.gnu-att.memory.load.{address}.u{access}.v1']=(access,access,'identity')
        for carrier in (16,32,64):
            if carrier > access:
                for short, projection in (('sx','sign_extend'),('zx','zero_extend')):
                    LOAD_ROLES[f'x86.gnu-att.memory.load.{address}.u{access}.{short}{carrier}.v1']=(access,carrier,projection)
STORE_WIDTHS = {f'x86.gnu-att.memory.store.{address}.u{width}.v1':width
                for address in ('gpr-address','gpr-address-disp32') for width in (8,16,32,64)}
CONTRACTS={**{key:('load',roles[0]) for key,roles in LOAD_ROLES.items()},
           **{key:('store',width) for key,width in STORE_WIDTHS.items()}}


def load_id(width,carrier,projection,displacement):
    suffix='gpr-address-disp32' if displacement else 'gpr-address'
    return next((key for key,roles in LOAD_ROLES.items()
                 if roles==(width,carrier,projection) and f'.{suffix}.' in key),None)


def load_template(semantic_id,address):
    width,carrier,projection=LOAD_ROLES[semantic_id]
    views={8:'b',16:'w',32:'k',64:'q'}
    if projection=='identity':
        # Preserve existing ordinary equal-width templates.
        dest='%0' if width in (32,64) else '%'+views[carrier]+'0'
        return 'mov'+{8:'b',16:'w',32:'l',64:'q'}[width]+' '+address+', '+dest
    if width==32 and projection=='zero_extend':
        return 'movl '+address+', %k0'  # AMD64 32-bit destination zeroes high bits.
    mnemonic=('movs' if projection=='sign_extend' else 'movz')
    mnemonic+={8:'b',16:'w',32:'l'}[width]+{16:'w',32:'l',64:'q'}[carrier]
    return mnemonic+' '+address+', %'+views[carrier]+'0'
