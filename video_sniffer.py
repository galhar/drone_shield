import av
import cv2
import time
from tellopy import Tello
import numpy as np

t = Tello()

video = av.open(t.get_video_stream(existing=True))
print(2)
fr_skip = 0

try:
	while True:
		for fr in video.decode(video=0):
			print(1)
			if fr_skip >= 0:
				fr_skip -= 1
				continue
			time = time.time()
			img = cv2.cvtColor(np.array(fr.to_image()), cv2.COLOR_RGB2BGR)
			cv2.imshow('Tello Video Stream', img)
			frame_T = fr.time_base
			elapsed_time = time.time() - time
			fr_skip = int(elapsed_time / frame_T)
except:
	pass
finally:
	t.quit()
