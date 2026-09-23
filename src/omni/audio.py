from __future__ import annotations
import math, struct, wave

def analyze_wav(path):
    with wave.open(path,"rb") as wav:
        channels,width,rate,frames=wav.getnchannels(),wav.getsampwidth(),wav.getframerate(),wav.getnframes()
        raw=wav.readframes(frames)
    if channels != 1 or width != 2:
        return {"status":"FAIL","reason":"EXPECTED_MONO_PCM16","channels":channels,"sample_width":width,"sample_rate":rate}
    if not raw:
        return {"status":"FAIL","reason":"EMPTY_AUDIO","channels":channels,"sample_width":width,"sample_rate":rate}
    samples=struct.unpack("<"+"h"*(len(raw)//2),raw); count=len(samples)
    peak=max(abs(x) for x in samples); mean=sum(samples)/count
    rms=math.sqrt(sum(float(x)*x for x in samples)/count)
    silence=sum(abs(x)<=128 for x in samples)/count
    clipping=sum(abs(x)>=32760 for x in samples)/count
    max_step=max((abs(samples[i]-samples[i-1]) for i in range(1,count)),default=0)
    duration=count/rate if rate else 0.0
    failures=[]
    if rate < 16000: failures.append("LOW_SAMPLE_RATE")
    if duration <= .02: failures.append("TOO_SHORT")
    if rms < 256: failures.append("NEAR_SILENCE")
    if abs(mean) > 2048: failures.append("EXCESSIVE_DC")
    if clipping > .001: failures.append("CLIPPING")
    if silence > .98: failures.append("MOSTLY_SILENT")
    return {"status":"PASS" if not failures else "FAIL","failures":failures,"channels":channels,
            "sample_width":width,"sample_rate":rate,"samples":count,"duration_s":duration,
            "peak":peak,"rms":rms,"dc_mean":mean,"silence_fraction":silence,
            "clipping_fraction":clipping,"max_step":max_step}
