import cv2
import os
ROOT = '/root/Desktop/pictures'
FACES = '/root/Desktop/faces'
TRAIN = '/root/Desktop/training'
def detect(srcdir=ROOT, tgtdir=FACES, train_dir=TRAIN):
for fname in os.listdir(srcdir):
1 if not fname.upper().endswith('.JPG'):
continue
fullname = os.path.join(srcdir, fname)
newname = os.path.join(tgtdir, fname)
2 img = cv2.imread(fullname)
if img is None:
continue
gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
training = os.path.join(train_dir,
'haarcascade_frontalface_alt.xml')
3 cascade = cv2.CascadeClassifier(training)
rects = cascade.detectMultiScale(gray, 1.3, 5)
try:
4 if rects.any():
print('Got a face')
5 rects[:, 2:] += rects[:, :2]
except AttributeError:
print(f'No faces found in {fname}.')
continue
# highlight the faces in the image
for x1, y1, x2, y2 in rects:
6 cv2.rectangle(img, (x1, y1), (x2, y2), (127,
255, 0), 2)
7 cv2.imwrite(newname, img)
if name == '__main__':
detect()
