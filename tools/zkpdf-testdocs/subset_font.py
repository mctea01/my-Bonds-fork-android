"""Create the redistributable synthetic-document font; run with python3 -I."""
import argparse
import hashlib
import json
from pathlib import Path
from fontTools import subset
from fontTools.ttLib import TTFont

TEXT = '仿在學證明出入境記錄合成測試姓名林學號出生日期科系資訊工程列印序證件口岸航班測北南學校資料不可作為真實文件零一二三四五六七八九0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz -:/'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('--index', type=int, default=2)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent / 'fonts'
    font = TTFont(args.source, fontNumber=args.index, recalcTimestamp=False)
    assert font['name'].getDebugName(6) == 'NotoSansCJKsc-Regular'
    assert font['name'].getDebugName(5).startswith('Version 2.004;')
    cmap = font.getBestCmap()
    chars = sorted(set(TEXT))
    assert all(ord(c) in cmap for c in chars)
    mapping = {c: int(cmap[ord(c)].removeprefix('cid')) for c in chars}
    widths = {str(mapping[c]): round(font['hmtx'][cmap[ord(c)]][0] * 1000 / font['head'].unitsPerEm) for c in chars}
    options = subset.Options()
    options.recalc_timestamp = False
    options.canonical_order = True
    sub = subset.Subsetter(options=options)
    sub.populate(unicodes=[ord(c) for c in chars])
    sub.subset(font)
    target = root / 'NotoSansCJKsc-Regular-subset.cff'
    target.write_bytes(font.getTableData('CFF '))
    metadata = {'family': 'Noto Sans CJK SC', 'version': '2.004', 'license': 'OFL-1.1',
                'source_sha256': hashlib.sha256(args.source.read_bytes()).hexdigest(),
                'subset_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                'cid': mapping, 'widths': widths}
    (root / 'mapping.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True)+'\n')

if __name__ == '__main__':
    main()
