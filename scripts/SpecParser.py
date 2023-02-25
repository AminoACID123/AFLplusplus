
import numpy as np
import PyPDF2
from pdf2image import convert_from_path
import cv2
import os
import re

MAX_LINE_BREAK = 25
MIN_LINE_LENGTH = 30
MAX_LINE_GRAY = 20
MAX_GRAY_GAP = 25
PAGE_MARGIN_LEFT = 246
PAGE_MARGIN_RIGHT = 1403
CELL_MARGIN_WIDTH = 2


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
        self.page = start

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
    
    def shrink_rect(self, x1, x2, y1, y2, w):
        x_min = min(x1, x2)
        x_max = max(x1, x2)
        y_min = min(y1, y2)
        y_max = max(y1, y2)
        return x_min + w, x_max - w, y_min + w, y_max - w

    def image_to_string(self, image):
        print(self.page)
        cv2.imwrite("/tmp/tmp.png", image)
        os.system("tesseract /tmp/tmp.png /tmp/res 2> /dev/null")
        with open('/tmp/res.txt', 'r') as f:
            text = f.read()
        os.system('rm /tmp/res.txt')
        return text
    
    def parse_cells(self, x_start, x_end, y_start, y_end):
        cells = []
        X, Y = [], []
        s = 1
        x1, x2, y1, y2 = self.shrink_rect(x_start, x_end, y_start, y_end, 3)
        for y in range(y1, y2):
            if s*(self.gray[y, x1] - self.gray[y+1, x1]) > MAX_GRAY_GAP:
                Y.append(y+1)
                s = -s
        for x in range(x1, x2):
            if self.gray[y1, x] - self.gray[y1, x+1] > MAX_GRAY_GAP:
                X.append(x+1)
        X = [x_start] + X + [x_end]
        Y = [y_start] + Y + [y_end]

        for i in range(len(Y)-1):
            cells.append([])
            y1, y2 = Y[i], Y[i+1]
            for j in range(len(X)-1):
                x1, x2 = X[j], X[j+1]
                x1, x2, y1, y2 = self.shrink_rect(x1, x2, y1, y2, 3)
                print((x1, x2, y1, y2))
                image = self.image[y1:y2,x1:x2]
                cells[-1].append(self.image_to_string(image))
        return cells

    def parse_command(self, X, Y):
        cells = self.parse_cells(X[0], X[1], Y[0], Y[1])
        for row in cells:
            cmd = row[0].replace('-','').replace('\n','').strip()
            ocf = eval(row[1].lower().replace('o','0'))
            params = [ re.sub('[\n\-\s]', '', param) for param in row[2].split(',')]
            ret_params = [ re.sub('[\n\-\s]', '', param) for param in row[3].split(',')]
            print((cmd, ocf, params, ret_params))

    def parse_form(self, start, end):
        x1, x2, y1, y2 = self.shrink_rect(PAGE_MARGIN_LEFT, PAGE_MARGIN_RIGHT, start, end, 2)
        X , Y= [PAGE_MARGIN_LEFT], [start]
        for x in range(PAGE_MARGIN_LEFT, PAGE_MARGIN_RIGHT):
            if self.gray[y1, x] - self.gray[y1, x+1] > MAX_GRAY_GAP:
                X.append(x)
                break
        for y in range(start, end):
            if self.gray[y, x1] - self.gray[y+1, x1] > MAX_GRAY_GAP:
                Y.append(y)
                break
        print(X, Y)
        x1, x2, y1, y2 = self.shrink_rect(X[0], X[1], Y[0], Y[1], 3)
        gray = self.gray[y1:y2,x1:x2]
        text = self.image_to_string(gray)
        X, Y = [PAGE_MARGIN_LEFT, PAGE_MARGIN_RIGHT], [Y[1], end]
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
            self.image = np.array(image)
            self.gray = self.rgb2gray(self.image)
            col = self.gray[:, PAGE_MARGIN_LEFT]
            vertical_lines = self.locate_vertical(col)
            for line in vertical_lines:
                self.parse_form(line[0], line[1])
            self.page += 1



if __name__ == "__main__":
    # text_extractor("Core_v5.3.pdf", 1846, 1848)
    PDFFormRecognizer("Core_v5.3.pdf", 1846, 2164).analyze()