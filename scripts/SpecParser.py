
import numpy as np
import PyPDF2
from pdf2image import convert_from_path
import cv2
import os

MAX_LINE_BREAK = 25
MIN_LINE_LENGTH = 30
MAX_LINE_GRAY = 20
MAX_GRAY_GAP = 25
PAGE_MARGIN_LEFT = 246
PAGE_MARGIN_RIGHT = 1403
CELL_MARGIN_WIDTH = 3


def clean_text(text):
    global event_start
    skip = False
    res = []
    i = 0
    for line in text:
        if line.strip() == "" or "This section is no longer used" in line:
            continue
        if line.strip() == "HCI commands and events":
            skip = True
            continue
        if line.strip() == "Host Controller Interface Functional Specification":
            skip = False
            continue
        if skip:
            continue
        if "7.7 EVENT" in line.strip():
            event_start = i
        res.append(line)
        i += 1
    return res



def text_extractor(path, start, end):
    with open(path, 'rb') as f:
        pdf = PyPDF2.PdfReader(f)
        for i in range(start, end + 1):
            page = pdf.pages[i]
            text = page.extract_text()
            print(text)

class PDFFormRecognizer:
    def  __init__(self, path, start, end) -> None:
        self.images = convert_from_path('Core_v5.3.pdf', fmt="jpeg", first_page=start, last_page=end)
        self.cells = 0

    def locate_vertical(self, arr):
        indices = np.flatnonzero(np.concatenate(([True], arr[1:]!=arr[:-1],[True])))
        runs = np.diff(indices).tolist()
        starts = indices[:-1].tolist()
        values = arr[starts].tolist()
        lines = list(zip(runs, starts, values))
        lines = [(line[1], line[0] + line[1]) for line in lines if line[2] < MAX_LINE_GRAY and line[0] > MIN_LINE_LENGTH]
        real_lines = []
        cur = 0
        for i in range(len(lines)-1):
            if i == 0:
                real_lines.append(lines[i])
            if lines[i+1][0] - lines[i][1] < MAX_LINE_BREAK:
                real_lines[cur] = (real_lines[cur][0], lines[i+1][1])
            else:
                real_lines.append(lines[i+1])
                cur += 1
        return real_lines
    
    def shrink_rect(self, x1, x2, y1, y2):
        x_min = min(x1, x2)
        x_max = max(x1, x2)
        y_min = min(y1, y2)
        y_max = max(y1, y2)
        return x_min + CELL_MARGIN_WIDTH, x_max - CELL_MARGIN_WIDTH, y_min + CELL_MARGIN_WIDTH, y_max - CELL_MARGIN_WIDTH

    def image_to_string(self, image):
        cv2.imwrite("/tmp/tmp.png", image)
        os.system("tesseract /tmp/tmp.png /tmp/res 2> /dev/null")
        with open('/tmp/res.txt', 'r') as f:
            text = f.read()
        os.system('rm /tmp/res.txt')
        return text

    def parse_command(self, X, Y):
        cell1 = self.shrink_rect(X[0], X[1], Y[1], Y[2])
        cell1_text = self.image_to_string(self.gray[cell1[2]:cell1[3],cell1[0]: cell1[1]])
        cell2 = self.shrink_rect(X[1], X[2], Y[1], Y[2])
        cell2_text = self.image_to_string(self.gray[cell2[2]:cell2[3],cell2[0]: cell2[1]])
        cell3 = self.shrink_rect(X[2], X[3], Y[1], Y[2])
        cell3_text = self.image_to_string(self.gray[cell3[2]:cell3[3],cell3[0]: cell3[1]])
        cell4 = self.shrink_rect(X[3], X[4], Y[1], Y[2])
        cell4_text = self.image_to_string(self.gray[cell4[2]:cell4[3],cell4[0]: cell4[1]])
        cmd = cell1_text.replace('-','').replace('\n','').strip()
        ocf = eval(cell2_text.lower().replace('o','0'))
        params = [ param.replace('\n','').replace(' ','') for param in cell3_text.split(',')]
        ret_params = [ param.replace('\n','').replace(' ','') for param in cell4_text.split(',')]
        print((cmd, ocf, params, ret_params))

    def locate_cells(self, start, end):
        x1, x2, y1, y2 = self.shrink_rect(PAGE_MARGIN_LEFT, PAGE_MARGIN_RIGHT, start, end)
        X , Y= [], []
        for x in range(x1, x2):
            if self.gray[y1, x] - self.gray[y1, x+1] > MAX_GRAY_GAP:
                X.append(x)
        for y in range(y1, y2):
            if self.gray[y, x1] - self.gray[y+1, x1] > MAX_GRAY_GAP:
                Y.append(y)
        X = [PAGE_MARGIN_LEFT] + X + [PAGE_MARGIN_RIGHT]
        Y = [start] + Y + [end]

        x1, x2, y1, y2 = self.shrink_rect(X[0], X[1], Y[0], Y[1])
        gray = self.gray[y1:y2,x1:x2]
        text = self.image_to_string(gray)
        if text.strip() == 'Command':
            self.parse_command(X, Y)
        elif text.strip() == 'Value':
            self
        # for i in range(len(X)-1):
        #     x1, x2 = X[i], X[i+1]
        #     for j in range(len(Y)-1):
        #         y1, y2 = Y[j], Y[j+1]
        #         x1, x2, y1, y2 = self.shrink_rect(x1, x2, y1, y2)
        #         gray = self.gray[y1:y2,x1:x2]
        #         cv2.imwrite(str(self.cells)+".png", gray)
        #         self.cells += 1

    def rgb2gray(self, rgb):
        r, g, b = rgb[:,:,0], rgb[:,:,1], rgb[:,:,2]
        gray = 0.2989 * r + 0.5870 * g + 0.1140 * b
        return gray.astype('int')

    def analyze(self):
        for image in self.images:
            self.image = image
            pixels = np.array(image)
            self.gray = self.rgb2gray(pixels)
            col = self.gray[:, PAGE_MARGIN_LEFT]
            vertical_lines = self.locate_vertical(col)
            for line in vertical_lines:
                self.locate_cells(line[0], line[1])



if __name__ == "__main__":
    # text_extractor("Core_v5.3.pdf", 1846, 1848)
    PDFFormRecognizer("Core_v5.3.pdf", 1846, 1949).analyze()