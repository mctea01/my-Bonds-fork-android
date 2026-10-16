# Synthetic TIFF samples for TiffDecoderTest: shapes and lines only, no real content.
import sys, os
from PIL import Image, ImageDraw
out = sys.argv[1]
def drawing(mode, size=(301, 203)):
    im = Image.new('L', size, 255)
    d = ImageDraw.Draw(im)
    d.rectangle([10, 10, 120, 60], outline=0, width=3)
    d.ellipse([150, 20, 280, 150], outline=0, width=5)
    for i in range(0, 300, 7):
        d.line([i, 170, i + 3, 200], fill=0, width=1)
    d.rectangle([30, 90, 90, 150], fill=0)
    d.polygon([(200, 160), (290, 190), (180, 199)], fill=0)
    return im if mode == 'L' else im.convert(mode)
bw = drawing('1')
bw.save(os.path.join(out, 'bw-expected.png'))
for comp in ['group4', 'group3', 'tiff_ccitt', 'packbits', 'tiff_lzw', 'tiff_adobe_deflate', 'raw']:
    bw.save(os.path.join(out, f'bw-{comp}.tiff'), compression=comp)
gray = drawing('L')
grad = Image.linear_gradient('L').resize(gray.size)
gray = Image.blend(gray, grad, 0.4)
gray.save(os.path.join(out, 'gray-expected.png'))
gray.save(os.path.join(out, 'gray-lzw.tiff'), compression='tiff_lzw')
rgb = Image.merge('RGB', (gray, grad, drawing('L')))
rgb.save(os.path.join(out, 'rgb-expected.png'))
rgb.save(os.path.join(out, 'rgb-lzw.tiff'), compression='tiff_lzw')
rgb.save(os.path.join(out, 'rgb-deflate.tiff'), compression='tiff_adobe_deflate')
pal = rgb.convert('P', palette=Image.ADAPTIVE, colors=16)
pal.convert('RGB').save(os.path.join(out, 'palette-expected.png'))
pal.save(os.path.join(out, 'palette-packbits.tiff'), compression='packbits')
bw.save(os.path.join(out, 'pages-group4.tiff'), compression='group4', save_all=True, append_images=[bw.rotate(180)])
