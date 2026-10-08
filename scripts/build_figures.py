"""Rebuild the two report diagrams as standard SVG and 2400-pixel PNG.

Requires Pillow and an installed Chinese font; no network or running services.
Use --font /path/to/a/CJK-font.ttf when automatic font discovery is unavailable.
SVG keeps editable text and vector geometry; PNG embeds the rendered glyphs.
"""
from __future__ import annotations

import argparse
import math
import os
from itertools import pairwise
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image, ImageDraw, ImageFont

INK = '#123E43'
TEAL = '#126A70'
PALE = '#EDF6F5'
LINE = '#80A8A9'
MUTED = '#48676A'
RUST = '#946044'
WARM = '#FBF5EF'
WHITE = '#FFFFFF'
WIDTH = 2400


def discover_font(override: Path | None) -> Path:
    if override:
        candidates = [override]
    else:
        candidates = []
        if os.environ.get('WINDIR'):
            directory = Path(os.environ['WINDIR'])/'Fonts'
            candidates += [directory/name for name in ('msyh.ttc', 'simhei.ttf', 'NotoSansSC-VF.ttf')]
        candidates += [Path('/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc'),
                       Path('/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc'),
                       Path('/System/Library/Fonts/PingFang.ttc')]
    for path in candidates:
        if path.is_file():
            ImageFont.truetype(str(path), 36)
            return path
    raise ValueError('A Chinese font is required; pass --font with an installed CJK font file')


class Diagram:
    """One coordinate system drives both SVG vectors and Pillow raster output."""
    def __init__(self, height: int, font_path: Path):
        self.height = height
        self.font_path = font_path
        bold = font_path.with_name('msyhbd.ttc')
        self.bold_path = bold if font_path.name.lower() == 'msyh.ttc' and bold.is_file() else font_path
        self.family = ImageFont.truetype(str(font_path), 36).getname()[0]
        self.scale = 2
        self.font_cache = {}
        self.image = Image.new('RGB', (WIDTH*self.scale, height*self.scale), WHITE)
        self.draw = ImageDraw.Draw(self.image)
        self.elements = [f'<rect width="{WIDTH}" height="{height}" fill="{WHITE}"/>']

    def font(self, size: int, bold: bool = False):
        key = (size, bold)
        if key not in self.font_cache:
            self.font_cache[key] = ImageFont.truetype(str(self.bold_path if bold else self.font_path), size*self.scale)
        return self.font_cache[key]

    def box(self, x, y, w, h, *, fill=WHITE, stroke=LINE, radius=18, width=3):
        self.elements.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" '
                             f'fill="{fill}" stroke="{stroke}" stroke-width="{width}"/>')
        s = self.scale
        self.draw.rounded_rectangle((x*s, y*s, (x+w)*s, (y+h)*s), radius=radius*s,
                                    fill=fill, outline=stroke, width=width*s)

    def text(self, x, y, value, *, size=42, bold=False, color=INK, center=False, max_width=None):
        if size < 40:
            raise ValueError('Report text must remain at least 40px at 2400px figure width')
        font = self.font(size, bold)
        width = self.draw.textlength(value, font=font)/self.scale
        if max_width is not None and width > max_width:
            raise ValueError(f'Text overflows by {width-max_width:.1f}px: {value}')
        if center:
            x -= width/2
        ascent = font.getmetrics()[0]/self.scale
        family = escape(self.family, {'"':'&quot;'})
        weight = '700' if bold else '400'
        self.elements.append(f'<text x="{x:.2f}" y="{y+ascent:.2f}" fill="{color}" '
                             f'font-family="{family}, Noto Sans CJK SC, sans-serif" '
                             f'font-size="{size}" font-weight="{weight}">{escape(value)}</text>')
        self.draw.text((x*self.scale, (y+ascent)*self.scale), value, font=font,
                       fill=color, anchor='ls')

    def line(self, points, *, color=TEAL, width=4, dashed=False, arrow=False, reverse_arrow=False):
        coords = ' '.join(f'{x},{y}' for x,y in points)
        dash = ' stroke-dasharray="14 10"' if dashed else ''
        self.elements.append(f'<polyline points="{coords}" fill="none" stroke="{color}" '
                             f'stroke-width="{width}" stroke-linejoin="round"{dash}/>')
        s = self.scale
        if dashed:
            for (x1,y1),(x2,y2) in pairwise(points):
                length=math.hypot(x2-x1,y2-y1)
                if not length: continue
                for start in range(0, math.ceil(length), 24):
                    end=min(start+14,length)
                    self.draw.line(((x1+(x2-x1)*start/length)*s,(y1+(y2-y1)*start/length)*s,
                                    (x1+(x2-x1)*end/length)*s,(y1+(y2-y1)*end/length)*s),
                                   fill=color,width=width*s)
        else:
            self.draw.line([(x*s,y*s) for x,y in points],fill=color,width=width*s,joint='curve')
        if arrow: self.arrowhead(points[-2],points[-1],color)
        if reverse_arrow: self.arrowhead(points[1],points[0],color)

    def arrowhead(self, before, tip, color):
        dx,dy=tip[0]-before[0],tip[1]-before[1]
        length=math.hypot(dx,dy)
        dx,dy=dx/length,dy/length
        points=[tip,(tip[0]-20*dx+9*dy,tip[1]-20*dy-9*dx),
                (tip[0]-20*dx-9*dy,tip[1]-20*dy+9*dx)]
        self.elements.append('<polygon points="'+' '.join(f'{x:.2f},{y:.2f}' for x,y in points)+f'" fill="{color}"/>')
        self.draw.polygon([(x*self.scale,y*self.scale) for x,y in points],fill=color)

    def save(self, output: Path, stem: str, title: str):
        content=(f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{self.height}" '
                 f'viewBox="0 0 {WIDTH} {self.height}" role="img" aria-label="{escape(title)}">'
                 f'<title>{escape(title)}</title><desc>Generated by scripts/build_figures.py. '
                 'Logical role and protocol diagrams, not a security proof.</desc>'
                 +''.join(self.elements)+'</svg>')
        (output/f'{stem}.svg').write_text(content,encoding='utf8')
        image=self.image.resize((WIDTH,self.height),Image.Resampling.LANCZOS)
        image.save(output/f'{stem}.png',dpi=(300,300),optimize=True)


def architecture(font: Path) -> Diagram:
    d=Diagram(1900,font)
    d.text(100,55,'隐私保护鲁棒联邦学习：逻辑架构',size=58,bold=True)
    d.text(102,144,'n 客户端 · w 边缘 · v 云；图示默认 6/3/4，门限 s/e 可配置',size=42,color=MUTED)
    d.box(100,245,400,180,fill=PALE,stroke=TEAL)
    d.text(300,267,'浏览器',size=50,bold=True,center=True)
    d.text(300,337,'控制 / 结果',size=42,center=True)
    d.box(705,245,1000,180,fill=PALE,stroke=TEAL)
    d.text(1205,265,'协调端',size=50,bold=True,center=True)
    d.text(1205,336,'任务固定 · 调度 · 记录与导出',size=42,center=True,max_width=940)
    d.box(1910,245,390,180,fill=PALE,stroke=TEAL)
    d.text(2105,267,'公开模型',size=50,bold=True,center=True)
    d.text(2105,337,'指标 / 决定',size=42,center=True)
    d.line([(500,335),(705,335)],arrow=True,reverse_arrow=True)
    d.line([(1705,335),(1910,335)],arrow=True)

    d.line([(890,425),(890,500),(425,500),(425,655)],arrow=True,reverse_arrow=True)
    d.box(130,542,590,60,fill=WHITE,stroke=WHITE,width=1)
    d.text(425,546,'参考模型 / 密封提交',size=42,center=True)
    d.line([(1205,425),(1205,655)],arrow=True,reverse_arrow=True)
    d.box(920,510,570,65,fill=WHITE,stroke=WHITE,width=1)
    d.text(1205,514,'签名核验 / 共同授权',size=42,center=True)
    d.line([(1520,425),(1520,475),(2000,475),(2000,655)],arrow=True,reverse_arrow=True)
    d.box(1720,532,560,60,fill=WHITE,stroke=WHITE,width=1)
    d.text(2000,536,'清单 / 部分结果',size=42,center=True)

    cards=[(100,655,650,'客户端 S1—Sn'),(865,655,680,'归属边缘 A1—Aw'),(1690,655,610,'云聚合 R1—Rv')]
    for x,y,w,title in cards:
        d.box(x,y,w,610,fill=WHITE,stroke=TEAL,width=4)
        d.box(x+2,y+2,w-4,106,fill=PALE,stroke=PALE,radius=16,width=1)
        d.text(x+w/2,y+22,title,size=50,bold=True,center=True,max_width=w-35)
    for i in range(6):
        x=133+(i%2)*305; y=795+(i//2)*100
        d.box(x,y,280,75,fill=PALE,stroke=LINE)
        d.text(x+140,y+9,f'S{i+1} → A{i%3+1}',size=42,center=True,max_width=264)
    for i in range(3):
        d.box(905,795+i*100,600,75,fill=PALE,stroke=LINE)
        owned=[index for index in range(1,7) if (index-1)%3==i]
        d.text(1205,804+i*100,f'A{i+1} 核验 S{owned[0]} / S{owned[1]}',size=42,center=True,max_width=565)
    for i in range(4):
        d.box(1730,795+i*80,530,75,fill=PALE,stroke=LINE)
        d.text(1995,804+i*80,f'R{i+1} 独立部分解密',size=42,center=True,max_width=495)
    for y,text in [(1105,'原始提交仅到归属边缘'),(1165,'样本私有 / 自身加密材料')]:
        d.text(130,y,text,size=42,max_width=590)
    for y,text in [(1105,'共享函数钥与签名核验结果'),(1165,'共同筛选；私有主密钥份额')]:
        d.text(900,y,text,size=42,max_width=610)
    for y,text in [(1130,'私有：自身函数材料'),(1190,'不持个体模型明文')]:
        d.text(1720,y,text,size=42,max_width=550)

    d.line([(1150,1265),(1150,1390),(420,1390),(420,1265)],dashed=True,arrow=True)
    d.text(785,1323,'客户端专属加密份额',size=42,center=True)
    d.line([(1280,1265),(1280,1470),(1995,1470),(1995,1265)],dashed=True,arrow=True)
    d.text(1660,1490,'聚合节点专属函数材料',size=42,center=True)
    d.text(100,1467,'实线：调度与可见结果',size=40,color=MUTED)
    d.text(100,1523,'虚线：密封转发，仅收件人解封',size=40,color=MUTED)

    d.box(100,1610,2200,260,fill=PALE,stroke=LINE)
    d.text(135,1624,'公开输出 / 协调端可见',size=50,bold=True)
    d.text(135,1692,'全局模型、客户端平方范数、授权内积/分数、获准清单及轮次/时间/通信元数据。',size=40,max_width=2130)
    d.text(135,1750,'边界：同机共享管理权限；三物理机未实测。',size=40,color=MUTED,max_width=2130)
    d.text(135,1805,'s/w 与 e/v 门限可配置；全员 DKG、主控单点；不声称完整论文安全证明。',size=40,color=MUTED,max_width=2130)
    return d


def round_flow(font: Path) -> Diagram:
    d=Diagram(2070,font)
    d.text(100,55,'一轮协议：从固定任务到下一轮模型',size=58,bold=True)
    d.text(103,145,'安全模式：授权绑定密文清单；失败保留证据，满足条件后才发布模型',size=42,color=MUTED)
    steps=[
        ('01  固定任务与轮次','n/w/v/s/e / 单一归属 / 模式 / 量化 / 参考摘要',
         '同业务轮次只允许一个上下文；完成后的重试返回既有结果'),
        ('02  全员 DKG 与函数钥共享','w 个边缘共同建钥；s/w 恢复客户端密钥',
         '任务首轮建钥；归属边缘获得验证函数钥份额'),
        ('03  本地训练与单归属提交','MNIST → 量化模型 → 密文与证明 → 归属边缘',
         '密封绑定客户端、轮次、模型摘要及部署拓扑'),
        ('04  归属边缘核验与共享','只核验所归属客户端；VerDec 内部计算评分',
         '共享签名评分、范数、摘要及密文核心'),
        ('05  共同筛选与一致授权','全部边缘用同一候选集合，按任务分组策略接纳',
         '至少 s 份一致签名绑定清单；默认重新组队'),
        ('06  云部分解密与 e/v 恢复','仅获准集合取得材料；至少 e 个云提供合法结果',
         '独立核验密文、授权及部分解密正确性证明'),
        ('07  独立计算并核对下一轮参考','协调端与密钥节点分别等权平均、量化并比较',
         '一致 → 发布新模型、固化状态，沿原策略进入下一轮'),
    ]
    for i,(title,line1,line2) in enumerate(steps):
        y=245+i*225
        d.box(165,y,1440,185,fill=PALE if i in (0,6) else WHITE,stroke=TEAL,width=3)
        d.text(200,y+12,title,size=50,bold=True,max_width=1370)
        d.text(203,y+77,line1,size=42,max_width=1364)
        d.text(203,y+126,line2,size=42,color=MUTED,max_width=1364)
        if i<6: d.line([(885,y+185),(885,y+225)],arrow=True)
    d.line([(165,1680),(76,1680),(76,330),(165,330)],dashed=True,arrow=True,width=3)
    for i,char in enumerate('下一轮'):
        d.text(24,925+i*55,char,size=40,color=TEAL)

    d.box(1805,460,495,275,fill=WARM,stroke=RUST)
    d.text(1840,480,'建钥中止',size=50,bold=True,color=RUST,max_width=425)
    d.text(1840,552,'任意边缘缺席',size=42,color=INK)
    d.text(1840,608,'转录或份额异常',size=42,max_width=425)
    d.text(1840,664,'不产生可用密钥',size=42,max_width=425)
    d.line([(1605,555),(1805,555)],color=RUST,arrow=True)

    d.box(1805,935,495,325,fill=WARM,stroke=RUST)
    d.text(1840,958,'拒绝 / 缺席',size=50,bold=True,color=RUST,max_width=425)
    d.text(1840,1031,'证明/筛选未通过',size=42,max_width=425)
    d.text(1840,1087,'缺席或拒绝',size=42)
    d.text(1840,1143,'固定策略可连带退出',size=42,max_width=425)
    d.text(1840,1199,'合格成员不足则中止',size=42,color=RUST,max_width=425)
    d.line([(1605,1005),(1805,1005)],color=RUST,arrow=True)
    d.line([(1605,1230),(1805,1230)],color=RUST,arrow=True)

    d.box(1805,1390,495,375,fill=WARM,stroke=RUST)
    d.text(1840,1410,'聚合中止',size=50,bold=True,color=RUST,max_width=425)
    d.text(1840,1485,'少于 e 份合法结果',size=42,max_width=425)
    d.text(1840,1541,'清单/密文不一致',size=42,max_width=425)
    d.text(1840,1597,'下一轮参考不一致',size=42,max_width=425)
    d.text(1840,1664,'→ 不发布新模型',size=42,color=RUST,max_width=425)
    d.line([(1605,1455),(1805,1455)],color=RUST,arrow=True)
    d.line([(1605,1680),(1805,1680)],color=RUST,arrow=True)

    d.box(165,1870,2135,150,fill=PALE,stroke=LINE)
    d.text(200,1889,'失败保留状态、原因和已有验证记录，不补造模型或准确率。',size=44,bold=True,max_width=2065)
    d.text(200,1953,'边界：s/w、e/v 可配置；全员 DKG 与主控单点；三物理机未实测。',size=40,color=MUTED,max_width=2065)
    return d


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--font',type=Path)
    parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'docs'/'submission'/'figures')
    args=parser.parse_args(argv)
    font=discover_font(args.font)
    args.output.mkdir(parents=True,exist_ok=True)
    architecture(font).save(args.output,'architecture','隐私保护鲁棒联邦学习逻辑架构')
    round_flow(font).save(args.output,'round-flow','联邦学习单轮协议流程')
    print('Built architecture.svg/png and round-flow.svg/png at 2400 pixels wide')


if __name__=='__main__':
    main()
