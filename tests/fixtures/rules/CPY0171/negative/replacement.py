import wave

with wave.open("a.wav", "rb") as reader:
    frames = reader.getnframes()
