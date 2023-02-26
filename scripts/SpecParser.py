"""
Experimental script which detects rectangles and lines on a PDF page.

It may or may not work (correctly)!
We are only covering the most simple cases: A general drawback is, that we are
ignoring any geometry changes, which might be established by "cm" commands.
More simplifying assumption can be found at the functions below.
"""
import fitz
import numpy as np

print(fitz.__doc__)

RECT_TO_START = 8
RECT_SHRINK_WIDTH = 3
RECT_MIN_SIZE = 10
POINT_SIZE = 3

class Point:
    def __init__(self, p) -> None:
        self.p = p
    
    def  __str__(self):
        X = str(int(self.p.x))
        Y = str(int(self.p.y))
        return str((X,Y))

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Point):
            return self.xeq(o) and self.yeq(o)
        return False
    
    def xeq(self, o):
        return abs(self.p.x - o.p.x) < 1
    
    def yeq(self, o):
        return abs(self.p.y - o.p.y) < 1
    
    
def pcmp(p1 : Point, p2 : Point):
    if p1 == p2:
        return 0
    # elif p1.xeq(p2):



class PDFFormRecognizer:
    def __init__(self, path, start, end):
        doc = fitz.open(path)  # the PDF
        self.start = start
        self.end = end
        self.doc = fitz.open()
        self.doc.insert_pdf(doc, from_page=start-1, to_page=end)
        self.shape = None
        self.form_areas = []
    
    def __del__(self):
        self.doc.save("x.pdf")

    def find_lines(self, page, cont):
        """Collect lines drawn on a page.

        For simplicity we assume the we always have this sequence of commands:

        x0 y0 m  % means go to point (x0, y0)
        x1 y1 l  % means draw line (from previous point) to point(x1, y1)

        We should also do the right thing, if an "l" command is preceeded by
        another "l".
        """
        ctm = page.transformation_matrix
        lines = []
        p1 = p2 = 0
        while p1 >= 0 and p1 < len(cont):
            try:
                p1 = cont.index("l", p2)
                p2 = p1 + 1
                y1 = float(cont[p1 - 1])
                x1 = float(cont[p1 - 2])
                if cont[p1 - 3] in ("m", "l"):
                    y0 = float(cont[p1 - 4])
                    x0 = float(cont[p1 - 5])
                else:
                    x0 = y0 = -1
                if x0 != -1:
                    point1 = fitz.Point(x0, y0) * ctm
                    point2 = fitz.Point(x1, y1) * ctm
                    lines.append((point1, point2))
                p1 = p2
            except:
                break

        return lines

    def rect_to_line(self, rect):
        delta_x = np.abs(rect.x0 - rect.x1)
        mean_x = np.mean([rect.x0 ,rect.x1])
        if delta_x < 10:
            p1 = fitz.Point(mean_x, rect.y0)
            p2 = fitz.Point(mean_x, rect.y1)
            return (p1, p2) if p1.y < p2.y else (p2, p1)
        delta_y = np.abs(rect.y0 - rect.y1)
        mean_y = np.mean([rect.y0, rect.y1])
        if delta_y < 10:
            p1 = fitz.Point(rect.x0, mean_y)
            p2 = fitz.Point(rect.x1, mean_y)
            return (p1, p2) if p1.x < p2.x else (p2, p1)
        return None

    def rect_to_keep(self, rect):
        return np.abs(rect.x0 -rect.x1) > RECT_MIN_SIZE and np.abs(rect.y0- rect.y1) > RECT_MIN_SIZE

    def transform_rect(self, page, x0, y0, x1, y1):
        ctm = page.transformation_matrix
        height = y1 - y0
        width = x1 - x0
        p = fitz.Point(x0, y0) * ctm + (0, -height)
        return fitz.Rect(p.x, p.y, p.x + width, p.y + height)

    def shrink_rect(self, rect):
        w = RECT_SHRINK_WIDTH
        return fitz.Rect(rect.x0 + w, rect.y0 + w, rect.x1 - w, rect.y1 - w)
    
    def vertex_valid(self, p):
        for r in self.form_areas:
            if p.p.y <= r[1].p.y and p.p.y >= r[0].p.y:
                return True
        return False

    def find_rects(self, page, cont):
        ctm = page.transformation_matrix
        rlist = []
        p1 = p2 = 0
        while p1 >= 0 and p1 < len(cont):
            try:
                p1 = cont.index("re", p2)
                p2 = p1 + 1
                height = float(cont[p1 - 1])
                width = float(cont[p1 - 2])
                y = float(cont[p1 - 3])
                x = float(cont[p1 - 4])
                p = fitz.Point(x, y) * ctm + (0, -height)
                rect = fitz.Rect(p.x, p.y, p.x + width, p.y + height)
                # rect = fitz.Rect(x, y, x + width, y + height)
                rlist.append(rect)
                p1 = p2
            except Exception as e:
                print(e)
                break
        return rlist
    
    def find_vertices(self, rects):
        vertices : list(Point) = []
        res : list(Point) = []
        for rect in rects:
            line = self.rect_to_line(rect)
            if line is not None:
                p1, p2 = Point(line[0]), Point(line[1])
                vertices += ([p1] + [p2])
                if p1.xeq(p2):
                    self.form_areas.append((p1, p2)) if (p1, p2) not in self.form_areas else None
            else:
                vertices += [Point(rect.tl)]
                vertices += [Point(rect.tr)]
                vertices += [Point(rect.bl)]
                vertices += [Point(rect.br)]
        [res.append(v) for v in vertices if v not in res]
        res = [v for v in res if self.vertex_valid(v)]
        return res

    
    def draw_rects(self, rects):
        for r in rects:
            self.shape.drawRect(r)
        self.shape.finish(color=(1, 0, 0), width=0.3)
        self.shape.commit()
    
    def draw_point(self, point):
        self.shape.drawLine(point + fitz.Point(0, POINT_SIZE), point + fitz.Point(0, -POINT_SIZE))
        self.shape.drawLine(point + fitz.Point(POINT_SIZE, 0), point + fitz.Point(-POINT_SIZE, 0))

    def draw_points(self, points):
        for v in points:
            self.draw_point(v.p)
        self.shape.finish(color=(0, 0, 1), width=2)

        for v in points:
            self.shape.insert_text(v.p + fitz.Point(2, 2), str(v), morph=(v.p,-fitz.Matrix(fitz.Identity)))
        self.shape.finish(color=(0, 0, 1), width=2)       
        self.shape.commit()
    
    def analyze(self):
        for page in self.doc.pages():
            # assert(page.get_contents) == 1
            self.page = page
            self.shape = page.new_shape()
            rects = []
            cont = []
            try:
                for xref in page.get_contents():
                    cont += self.doc.xref_stream(xref).decode().split()
            except:
                continue

            rects = self.find_rects(page, cont)[RECT_TO_START:]
            # rects = [rect for rect in rects if not self.rect_to_keep(rect)]
            # # for rect in rects:
            # #     text = page.get_textbox(rect)
            # #     print(text)
            # #     print('------------------------------')
            # print(rects)
            # self.draw_rects([rect for rect in rects])
            vertices = self.find_vertices(rects)
            self.draw_points(vertices)
            print(self.form_areas)


PDFFormRecognizer("test.pdf", 1, 1).analyze()

# # create a drawing shape and draw the lines and the rectangles ...
# # just to demonstrate things are working
# shape = page.new_shape()

# # draw all the rectangles

# for i, r in enumerate(rects[8:]):
#     line = rect_to_line(r)
#     if line is None:
#         text = page.get_textbox(r)
#         print(text)
#         shape.drawRect(shrink_rect(r))
#         shape.finish(color=(1, 0, 0), width=0.3)
#         if i== 5:
#             break
#     # else:
#     #     shape.drawLine(line[0], line[1])
#     #     shape.finish(color=(0, 0, 1), width=2) 
#   # with a thin red line

# # draw all the lines
# #for l in lines:
# #    shape.drawLine(l[0], l[1])

# for word in page.get_text("words"):
#     #print(word)
#     shape.drawRect(transform_rect(page, word[0], word[1], word[2], word[3]))

# shape.finish(color=(0, 0, 1), width=2)  # with a thick blue line

# shape.commit()  # commit the shape to the page
# doc.save("x.pdf")  # save everything to a new PDF