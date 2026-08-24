#!/usr/bin/env python3
"""Create the captioned AI-DFIR v1.6 synthetic demo MP4.

Requires Pillow and FFmpeg. No production credentials or network access.
"""
from __future__ import annotations
import json, math, shutil, subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT=Path(__file__).resolve().parents[1]
DEMO=ROOT/'docs/demo'
ASSETS=DEMO/'assets/generated'
OUT=DEMO/'AI-DFIR-v1.6.0-demo.mp4'
W,H=1280,720
BG='#08111f'; PANEL='#101c2f'; PANEL2='#13233b'; TEXT='#e8f0fb'; MUTED='#91a4bd'; LINE='#263b58'; ACCENT='#7db0ff'; GREEN='#4ade80'; AMBER='#fbbf24'; RED='#fb7185'
FONT_REG='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
FONT_BOLD='/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'


def font(size,bold=False):
    p=FONT_BOLD if bold else FONT_REG
    return ImageFont.truetype(p,size)

def text(draw,xy,s,size=28,color=TEXT,bold=False,anchor=None):
    draw.text(xy,s,font=font(size,bold),fill=color,anchor=anchor)

def rounded(draw,box,fill=PANEL,outline=LINE,r=18,width=2):
    draw.rounded_rectangle(box,radius=r,fill=fill,outline=outline,width=width)

def wrap(s,n=52):
    words=s.split();lines=[];cur=[]
    for w in words:
        if len(' '.join(cur+[w]))>n and cur:lines.append(' '.join(cur));cur=[w]
        else:cur.append(w)
    if cur:lines.append(' '.join(cur))
    return lines

def header(draw,kicker,title,subtitle=None):
    text(draw,(64,52),kicker.upper(),18,ACCENT,True)
    text(draw,(64,80),title,36,TEXT,True)
    if subtitle:
        text(draw,(64,126),subtitle,20,MUTED)
    draw.line((64,164,W-64,164),fill=LINE,width=2)

def footer(draw,idx,total):
    text(draw,(64,H-36),'AI-DFIR v1.6.0 • Synthetic demonstration • No production data',15,MUTED)
    text(draw,(W-64,H-36),f'{idx}/{total}',15,MUTED,anchor='ra')

def terminal(draw,box,lines,title='Terminal'):
    x1,y1,x2,y2=box;rounded(draw,box,fill='#07101d',outline=LINE,r=14)
    draw.rectangle((x1,y1,x2,y1+40),fill='#0d1b2d')
    for i,c in enumerate([RED,AMBER,GREEN]):draw.ellipse((x1+16+i*22,y1+14,x1+26+i*22,y1+24),fill=c)
    text(draw,(x1+92,y1+12),title,15,MUTED,True)
    y=y1+58
    for line,col in lines:
        text(draw,(x1+22,y),line,17,col,False);y+=27
        if y>y2-24:break

def kpi(draw,x,y,label,value,color=TEXT,w=230):
    rounded(draw,(x,y,x+w,y+92),fill=PANEL2,outline=LINE,r=16)
    text(draw,(x+18,y+16),label,16,MUTED,True)
    text(draw,(x+18,y+47),value,29,color,True)

def finding(draw,x,y,severity,title,detail,w=540):
    color={'CRITICAL':RED,'HIGH':AMBER,'PASS':GREEN,'INFO':ACCENT}.get(severity,ACCENT)
    rounded(draw,(x,y,x+w,y+86),fill=PANEL2,outline=LINE,r=12)
    text(draw,(x+14,y+13),severity,14,color,True)
    text(draw,(x+110,y+12),title,18,TEXT,True)
    text(draw,(x+14,y+46),detail,15,MUTED)

def slide1():
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im)
    text(d,(W//2,205),'AI-DFIR',66,TEXT,True,anchor='ma')
    text(d,(W//2,290),'v1.6.0',31,ACCENT,True,anchor='ma')
    text(d,(W//2,355),'AI Incident Response & Digital Forensics',30,TEXT,True,anchor='ma')
    text(d,(W//2,407),'Production Assurance • Runtime Trust • Human-in-the-Loop',21,MUTED,anchor='ma')
    rounded(d,(255,500,1025,585),fill=PANEL2,outline=LINE,r=20)
    text(d,(W//2,527),'What executed? What influenced it? What authority existed?',19,TEXT,True,anchor='ma')
    text(d,(W//2,559),'What trustworthy evidence proves the path to consequence?',18,ACCENT,anchor='ma')
    return im

def slide2():
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im);header(d,'Reproducible demo','Install and validate without real incident data','All demo inputs are synthetic and generated locally.')
    terminal(d,(64,205,1216,585),[
      ('$ ./install.sh default',ACCENT),
      ('Creating isolated .venv ...',MUTED),
      ('$ source .venv/bin/activate',ACCENT),
      ('$ python tests/generate_test_corpus.py',ACCENT),
      ('Generated synthetic evidence for 111 Evidence Packs',GREEN),
      ('$ python tests/run_synthetic_scenarios.py',ACCENT),
      ('19 / 19 detector domains PASS',GREEN),
      ('$ python scripts/release_check.py --quick',ACCENT),
      ('Release gate: PASS',GREEN),
    ])
    footer(d,2,9);return im

def slide3():
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im);header(d,'Evidence quality','Presence is not proof','Evidence is evaluated for integrity, attribution, time relevance, completeness, and corroboration.')
    kpi(d,64,210,'Evidence Packs','111',GREEN);kpi(d,318,210,'Matrix result','111 / 111 PASS',GREEN,290);kpi(d,632,210,'Detector domains','19 / 19 PASS',GREEN,270);kpi(d,926,210,'Source evidence','HASH-BOUND',ACCENT,290)
    finding(d,64,340,'INFO','PRESENT_UNVALIDATED','A matching filename exists, but required trust checks are incomplete.',560)
    finding(d,650,340,'PASS','VALIDATED','Parse, attribution, and acquisition-hash requirements passed.',566)
    finding(d,64,447,'PASS','AUTHORITATIVE','Validated evidence promoted only through verified signed acquisition trust.',560)
    finding(d,650,447,'HIGH','INCOMPLETE / CONFLICTING','Cannot satisfy a conclusion gate; must remain visible to the analyst.',566)
    footer(d,3,9);return im

def slide4():
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im);header(d,'Representation integrity','What the AI reads may not be what the human sees','EvilFont-style glyph remapping and hidden representation channels are first-class evidence.')
    rounded(d,(64,210,560,570),fill=PANEL,outline=LINE,r=16)
    text(d,(88,235),'Machine-readable representation',18,MUTED,True)
    text(d,(88,286),'"approve transfer immediately"',25,RED,True)
    draw_y=350
    text(d,(88,draw_y),'Font / document signals',18,TEXT,True)
    text(d,(98,draw_y+42),'• per-character font switching',17,MUTED)
    text(d,(98,draw_y+74),'• glyph outline collapse',17,MUTED)
    text(d,(98,draw_y+106),'• machine / visible disagreement',17,MUTED)
    rounded(d,(600,210,1216,570),fill=PANEL,outline=LINE,r=16)
    text(d,(624,235),'Human-visible representation',18,MUTED,True)
    text(d,(624,286),'"quarterly benefits reminder"',25,GREEN,True)
    finding(d,624,350,'CRITICAL','representation divergence','Source bytes preserved; independent visible representation differs.',548)
    finding(d,624,455,'CRITICAL','EvilFont-style mechanism','Remapped glyph structure is detected independently of tool naming.',548)
    footer(d,4,9);return im

def slide5():
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im);header(d,'Runtime trust','Identity, state, and authority are evaluated at incident time','Signature validity is not the same as trust. Correlation is not the same as causation.')
    kpi(d,64,208,'Agent Card JWS','VALID',GREEN);kpi(d,318,208,'Signing key','REVOKED',RED);kpi(d,572,208,'Tenant binding','MISMATCH',RED);kpi(d,826,208,'Authority','EXCEEDED',RED);kpi(d,1080,208,'Causal edge','SUPPORTED',GREEN,136)
    finding(d,64,335,'CRITICAL','a2a_undeclared_skill_invoked','Observed skill was not declared by the trusted Agent Card.',560)
    finding(d,650,335,'CRITICAL','credential_scope_expansion','Delegated credential gained additional scope in the exchange.',566)
    finding(d,64,442,'CRITICAL','action_exceeded_temporal_authority','Action fell outside valid grant/approval conditions at that timestamp.',560)
    finding(d,650,442,'HIGH','memory_cross_tenant_read','Persistent memory was read across a tenant boundary.',566)
    footer(d,5,9);return im

def slide6():
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im);header(d,'Analyst Workbench','One read-only case view across the AI execution stack','Synthetic DEMO-001 combines representation, runtime, A2A, MCP, provider, and collection evidence.')
    # dashboard-like panel
    rounded(d,(64,198,1216,614),fill=PANEL,outline=LINE,r=16)
    text(d,(88,218),'DEMO-001  •  Synthetic Agentic AI Incident',22,TEXT,True)
    text(d,(88,252),'READ-ONLY',14,GREEN,True)
    kpi(d,88,292,'Representation findings','13',RED,235)
    kpi(d,344,292,'Runtime trust findings','21',RED,235)
    kpi(d,600,292,'A2A findings','4',AMBER,210)
    kpi(d,832,292,'Platform assurance','DEGRADED',AMBER,300)
    finding(d,88,410,'CRITICAL','machine_visible_text_disagreement','Machine-readable document semantics differ from visible content.',510)
    finding(d,622,410,'CRITICAL','a2a_unapproved_authority_escalation','Observed delegated authority increased without required approval.',566)
    finding(d,88,513,'HIGH','provider_telemetry_incomplete','Evidence source cannot answer the full incident window.',510)
    finding(d,622,513,'INFO','typed causal graph','Causal claims retain explicit evidence-backed edge semantics.',566)
    footer(d,6,9);return im

def slide7():
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im);header(d,'Platform assurance','Can the forensic platform itself be trusted right now?','A missing record cannot be interpreted as clean evidence if the collection path was unhealthy.')
    controls=[('Metadata DB / RLS','PASS',GREEN),('Evidence WORM','PASS',GREEN),('KMS / envelope keys','PASS',GREEN),('SPIFFE / mTLS','PASS',GREEN),('Provider telemetry','DEGRADED',AMBER),('Collector coverage','DEGRADED',AMBER),('DR restore','PASS',GREEN),('Release integrity','PASS',GREEN)]
    x,y=64,210
    for i,(name,status,col) in enumerate(controls):
        xx=x+(i%2)*580;yy=y+(i//2)*88
        rounded(d,(xx,yy,xx+548,yy+68),fill=PANEL2,outline=LINE,r=12)
        text(d,(xx+18,yy+13),name,18,TEXT,True);text(d,(xx+522,yy+14),status,17,col,True,anchor='ra')
    rounded(d,(64,585,1216,646),fill='#2a1f08',outline=AMBER,r=12)
    text(d,(86,604),'DEGRADED: provider/collector gaps stay visible and can block unsupported conclusions.',18,AMBER,True)
    footer(d,7,9);return im

def slide8():
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im);header(d,'Human in the loop','Automation organizes evidence. Investigators own judgment.','High-impact decisions remain explicit human gates.')
    gates=[('Attribution','Human review required'),('Destructive containment','Authorized human approval'),('Legal-hold release','Evidence custodian approval'),('External evidence sharing','Privacy / legal review'),('Case closure','Independent peer review')]
    y=215
    for i,(a,b) in enumerate(gates):
        rounded(d,(110,y,1170,y+66),fill=PANEL2,outline=LINE,r=14)
        text(d,(138,y+18),a,19,TEXT,True);text(d,(1140,y+18),b,18,ACCENT,True,anchor='ra');y+=79
    text(d,(W//2,630),'The tool may prioritize a finding. It does not get to invent certainty.',21,MUTED,True,anchor='ma')
    footer(d,8,9);return im

def slide9():
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im)
    text(d,(W//2,150),'AI-DFIR v1.6.0',45,TEXT,True,anchor='ma')
    text(d,(W//2,220),'Production-capable software ≠ production-ready deployment',26,AMBER,True,anchor='ma')
    rounded(d,(245,292,1035,505),fill=PANEL,outline=LINE,r=18)
    lines=['HA PostgreSQL + tenant isolation','WORM evidence + KMS/HSM','OIDC/MFA + SPIFFE/mTLS','Provider certification + collection health','DR / failover / SLO evidence','Independent security assessment + HITL']
    for i,line in enumerate(lines):
        text(d,(285,320+i*30),'✓',20,GREEN,True);text(d,(320,320+i*30),line,18,TEXT)
    text(d,(W//2,558),'Run production_readiness_v16.py against the actual deployment.',20,ACCENT,True,anchor='ma')
    text(d,(W//2,615),'github-ready • reproducible synthetic tests • evidence-backed conclusions',18,MUTED,anchor='ma')
    return im

SLIDES=[slide1,slide2,slide3,slide4,slide5,slide6,slide7,slide8,slide9]
DURS=[6,10,10,11,12,12,12,10,8]

def run(cmd):
    cp=subprocess.run(cmd,text=True,capture_output=True)
    if cp.returncode:raise RuntimeError(cp.stderr)

def main():
    if not shutil.which('ffmpeg'):raise SystemExit('ffmpeg is required')
    ASSETS.mkdir(parents=True,exist_ok=True)
    clips=[]
    for i,(fn,dur) in enumerate(zip(SLIDES,DURS),1):
        png=ASSETS/f'slide-{i:02}.png';clip=ASSETS/f'clip-{i:02}.mp4'
        fn().save(png,quality=95)
        fade_out=max(0.1,dur-0.45)
        run(['ffmpeg','-y','-loglevel','error','-loop','1','-i',str(png),'-t',str(dur),'-r','30',
             '-vf',f'fade=t=in:st=0:d=0.35,fade=t=out:st={fade_out}:d=0.35,format=yuv420p',
             '-c:v','libx264','-preset','medium','-crf','20','-movflags','+faststart',str(clip)])
        clips.append(clip)
    concat=ASSETS/'concat.txt';concat.write_text('\n'.join(f"file '{p.as_posix()}'" for p in clips)+'\n')
    run(['ffmpeg','-y','-loglevel','error','-f','concat','-safe','0','-i',str(concat),'-c','copy','-movflags','+faststart',str(OUT)])
    print(json.dumps({'status':'PASS','video':str(OUT),'duration_seconds':sum(DURS),'slides':len(SLIDES),'bytes':OUT.stat().st_size},indent=2))
if __name__=='__main__':main()
