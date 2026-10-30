"""Makes signed.jpg and signed.png: python3 generate.py <dir with chain.pem and leaf.key> <out dir> (needs c2pa-python, Pillow)."""
import sys, json, io, c2pa
from PIL import Image
pki = sys.argv[1]; out = sys.argv[2]
for fmt, mime, ext in (("JPEG","image/jpeg","jpg"),("PNG","image/png","png")):
    img = Image.new("RGB", (16, 16), (200, 30, 30))
    src = io.BytesIO(); img.save(src, fmt); src.seek(0)
    manifest = {
        "claim_generator_info": [{"name": "diw-test", "version": "1.0"}],
        "title": "測試圖片." + ext,
        "format": mime,
        "assertions": [
            {"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"}]}},
            {"label": "stds.schema-org.CreativeWork", "data": {"@context": "http://schema.org/", "@type": "CreativeWork", "author": [{"@type": "Person", "name": "測試作者"}]}},
        ],
    }
    info = c2pa.C2paSignerInfo(alg=b"es256", sign_cert=open(pki+"/chain.pem","rb").read(), private_key=open(pki+"/leaf.key","rb").read(), ta_url=None)
    signer = c2pa.Signer.from_info(info)
    with c2pa.Builder(json.dumps(manifest)) as b:
        dst = io.BytesIO()
        b.sign(signer, mime, src, dst)
        open(f"{out}/signed.{ext}","wb").write(dst.getvalue())
    print(ext, len(dst.getvalue()))
