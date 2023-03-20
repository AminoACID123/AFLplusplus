#!/usr/bin/env python3

"""
Experimental script which detects rectangles and lines on a PDF page.

It may or may not work (correctly)!
We are only covering the most simple cases: A general drawback is, that we are
ignoring any geometry changes, which might be established by "cm" commands.
More simplifying assumption can be found at the functions below.
"""


import fitz
import numpy as np
import functools
import re
import pprint
import json
from nltk.parse.corenlp import CoreNLPDependencyParser
import nltk
import Levenshtein




print(fitz.__doc__)

TEXT_TO_START = 5
RECT_TO_START = 8
RECT_SHRINK_WIDTH = 3
RECT_MIN_SIZE = 10
POINT_SIZE = 3
ACTIONS = ['send', 'create', 'complete', 'return']

SERVER_IP = 'http://114.212.83.191'
SERVER_PORT = '9000'

class Point(fitz.Point):
    def __init__(self, p) -> None:
        super().__init__(p)
    
    def __eq__(self, o: object) -> bool:
        if isinstance(o, Point):
            return self.xeq(o) and self.yeq(o)
        return False
    
    def xeq(self, o):
        return abs(self.x - o.x) < 1
    
    def yeq(self, o):
        return abs(self.y - o.y) < 1
    
    
def pcmp(p1 : Point, p2 : Point):
    if p1.yeq(p2):
        return p1.x - p2.x
    return p1.y - p2.y

class Form:
    def __init__(self, y0, y1) -> None:
        self.y0 = min(y0, y1)
        self.y1 = max(y0, y1)
        self.prev = 0
        self.X = []
        self.Y = []
        pass

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Form):
            return abs(self.y0 - o.y0) < 1 and abs(self.y1 - o.y1) < 1
        return False
    
    def __getitem__(self, index):
        return self.cells[index]
    
    def __str__(self) -> str:
        text = ''
        for row in self.cells:
            for col in row:
                text = text + col + '\t'
            text += '\n'
        return text
    
    def add_vertex(self, v):
        if self.vertex_valid(v):
            self.X.append(v.x)
            self.Y.append(v.y)
    
    def get_vertices(self):
        return self.vertices

    def form(self, page):
        self.page = page
        i = 0
        self.X = sorted(self.X)
        while i < len(self.X) - 1:
            if abs(self.X[i] - self.X[i+1]) < 10:
                self.X.pop(i+1)
            else:
                i += 1

        i = 0
        self.Y = sorted(self.Y)
        while i < len(self.Y) - 1:
            if abs(self.Y[i] - self.Y[i+1]) < 10:
                self.Y.pop(i+1)
            else:
                i += 1
        self.vertices_to_cells()

    def vertices_to_cells(self):
        self.header = ''
        self.cells = []
        self.cols = len(self.X) - 1
        self.rows = len(self.Y) - 1
        if  self.rows < 1 or self.cols < 1:
            self.cells.append([''])
            return

        for i in range(self.rows):
            self.cells.append([])
            y0 = self.Y[i]
            y1 = self.Y[i+1]
            for j in range(self.cols):
                x0 = self.X[j]
                x1 = self.X[j+1]
                self.cells[-1].append(self.page.get_textbox(fitz.Rect(x0-5, y0-5, x1+5, y1+5)))

        header = self.page.get_textbox(fitz.Rect(self.X[0]-10, self.Y[0]-60 , self.X[-1]+10, self.Y[0])).replace('-\n', '').split()
        self.pname = None
        self.size = None
        for i in range(len(header)-1):
            tok = header[i]
            next_tok = header[i+1]
            if next_tok == 'Size:':
                self.pname = tok[:-1]
                for j in range(i, len(header)):
                    if header[j].startswith('octet'):
                        try:
                            self.size = int(header[j-1])
                        except:
                            pass
                        return
            

    def vertex_valid(self, p : Point):
        if abs(self.y0 - p.y) < 1 or abs(self.y1 - p.y) < 1:
            return True 
        return p.y > self.y0 and p.y < self.y1
    

def fcmp(f1, f2):
    return f1.y0 - f2.y0

class HCIAnalyzer:
    def __init__(self, path, start, end):
        doc = fitz.open(path)
        self.start = start
        self.end = end
        self.doc = fitz.open()
        self.doc.insert_pdf(doc, from_page=start-1,to_page=end)
        self.pageno = 0
        self.forms = []
        self.event_descs = []
        self.event_desc_on = False
    
    def __del__(self):
        self.doc.save("x.pdf")

    def find_lines(self, page, cont):
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

    def transform_rect(self, x0, y0, x1, y1):
        ctm = self.page.transformation_matrix
        height = y1 - y0
        width = x1 - x0
        p = fitz.Point(x0, y0) * ctm + (0, -height)
        return fitz.Rect(p.x, p.y, p.x + width, p.y + height)

    def shrink_rect(self, rect):
        w = RECT_SHRINK_WIDTH
        return fitz.Rect(rect.x0 + w, rect.y0 + w, rect.x1 - w, rect.y1 - w)
    
    def vertex_valid(self, p):
        for r in self.form_areas:
            if r[1].yeq(p) or r[0].yeq(p):
                return True
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
                #rect = fitz.Rect(x, y, x + width, y + height)
                rlist.append(rect)
                p1 = p2
            except Exception as e:
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
                    form = Form(p1.y, p2.y)
                    self.forms[-1].append(form) if form not in self.forms[-1] else None
            else:
                vertices += [Point(rect.tl)]
                vertices += [Point(rect.tr)]
                vertices += [Point(rect.bl)]
                vertices += [Point(rect.br)]
                form = Form(rect.y0, rect.y1)
                self.forms[-1].append(form) if form not in self.forms[-1] else None

        temp = sorted(self.forms[-1], key=functools.cmp_to_key(fcmp))
        self.forms[-1] = []
        for i in range(len(temp)-1):
            if i == 0:
                self.forms[-1].append(Form(temp[i].y0, temp[i].y1))
            if abs(temp[i].y1 - temp[i+1].y0) < 1 or temp[i].y1 > temp[i+1].y0:
                self.forms[-1][-1].y1 = max(temp[i].y1, temp[i+1].y1)
            else:
                self.forms[-1].append(temp[i+1])

        [res.append(v) for v in vertices if v not in res]
        for v in res:
            for form in self.forms[-1]:
                form.add_vertex(v)
        for form in self.forms[-1]:
            form.form(self.page)
        
    
    def draw_rects_2d(self, rects):
        for row in rects:
            for col in row:
                # col = self.transform_rect(col.x0, col.y0, col.x1, col.y1)
                self.shape.drawRect(col)
        self.shape.finish(color=(1, 0, 0), width=0.3)
        self.shape.commit()

    def draw_rects_1d(self, rects):
        for rect in rects:
            # rect = self.transform_rect(rect.x0, rect.y0, rect.x1, rect.y1)
            self.shape.drawRect(rect)
        self.shape.finish(color=(1, 0, 0), width=0.3)
        self.shape.commit()
    
    def draw_point(self, point):
        self.shape.drawLine(point + fitz.Point(0, POINT_SIZE), point + fitz.Point(0, -POINT_SIZE))
        self.shape.drawLine(point + fitz.Point(POINT_SIZE, 0), point + fitz.Point(-POINT_SIZE, 0))

    def draw_points(self, X, Y):
        for x in X:
            for y in Y:
                self.draw_point(fitz.Point(x, y))
        self.shape.finish(color=(0, 0, 1), width=2)

        self.shape.commit()
    
    def draw_lines(self, lines):
        for line in lines:
            self.shape.drawLine(line[0], line[1])
        self.shape.finish(color=(1, 0, 1), width=1.5)       
        self.shape.commit()         

    def analyze(self):
        for page in self.doc.pages():
            self.analyze_page_text(page)
            self.analyze_page_forms(page)
    
    def analyze_page_text(self, page):
        for i, block in enumerate(page.get_text('blocks', sort=True)):
            text =  block[4]
            if re.match("7\..*", text.strip()) is not None or \
                re.match("7\..*", text.strip()) is not None or \
                "appendix" in text.lower():
                self.event_desc_on = False
            elif "event(s) generated" in text.lower():
                self.event_desc_on = True
                self.event_descs.append('')
            elif self.event_desc_on:
                if text.strip() == "HCI commands and events" or \
                    "Revision Date" in text or \
                    "Bluetooth SIG Proprietary" in text or \
                    "BLUETOOTH CORE SPECIFICATION Version" in text or \
                    "Host Controller Interface Functional Specification" == text.strip() or \
                    'this section is no longer used' in text.lower() or \
                    re.match("page [0-9]*", text) is not None:
                    continue
                text = text.replace('-\n', '').replace('\n', ' ')
                self.event_descs[-1] += text

    def analyze_page_forms(self,  page):
        self.pageno += 1
        # print(self.pageno)
        # assert(page.get_contents) == 1
        self.page = page
        self.shape = page.new_shape()
        self.forms.append([])
        rects = []
        cont = []
        for xref in page.get_contents():
            try:
                cont += self.doc.xref_stream(xref).decode(errors='ignore').split()
            except:
                print(self.doc.xref_stream(xref))
                continue

        rects = self.find_rects(page, cont)[RECT_TO_START:]
        self.draw_rects_1d([rect for rect in rects])
        self.find_vertices(rects)
        #self.draw_points(self.forms[-1][0].X, self.forms[-1][0].Y)
        # for form in self.forms[-1]:
        #     print(form)
    
    def analyze_domain(self, form):
        dom = []
        if form[0][0].strip() != 'Value':
            return dom
        for i in range(1, form.rows):
            text = form[i][0].split('=')[-1].strip().replace('-', '').replace('\n', '')
            if 'All' in text:
                pass
            elif 'XX' in text:
                dom.append([])
            elif 'octet' in text.lower():
                dom.append([])
            elif 'Name' in text:
                dom.append([-1, -1])
            elif ',' in text:
                for val in text.split(','):
                    if 'to' in val:
                        vals = val.split('to')
                        dom.append([eval(vals[0]), eval(vals[1])])
            elif 'to' in text:
                vals = text.split('to')
                dom.append([eval(vals[0]), eval(vals[1])])
            else:
                try:
                    val = eval(text)
                    dom.append([val, val])
                except:
                    pass
        return dom
        
    def analyze_data(self):
        #cmd = {'name': '', 'ogf': 0, 'ocf': 0, 'parameters': [], 'return_parameters:': []}
        ogf = 0
        self.commands = []
        self.events = []
        cur = ''
        for forms in self.forms:
            for form in forms:
                ty = form[0][0].strip()
                if ty == '':
                    pass
                elif ty == "Command":
                    ocf = []
                    params = dict()
                    rparams = dict()
                    cur = ty
                    name = form[1][0].strip().replace('-', '').replace('\n','').split('[')[0].strip()
                    for i in range(1, form.rows):
                        ocf.append([eval(form[i][1].strip().replace('\n',''))])
                    for i in range(1, form.rows):
                        pnames = [pname for pname in form[i][2].replace(']', '],').split(',') if pname != '']
                        ocf[i-1].append(len(pnames))
                        for pname in pnames:
                            pname = pname.strip().replace('\n','').replace('-','')
                            params[pname] = {'size': -1}
                    for i in range(1, form.rows):
                        pnames = [pname for pname in form[i][3].replace(']', '],').split(',') if pname != '']
                        ocf[i-1].append(len(pnames))
                        for pname in pnames:
                            pname = pname.strip().replace('\n','').replace('-','')
                            rparams[pname] = {'size': -1}
                    if ocf[0][0] == 1:
                        ogf += 1
                    elif "HCI_LE_" in name:
                        ogf = 8
                    # params = list(map(lambda i: {'name': params[i], 'size': -1}, range(len(params))))
                    # rparams = list(map(lambda i: {'name': rparams[i], 'size': -1}, range(len(rparams))))
                    self.commands.append({'name': name, 'ogf': ogf, 'ocf':ocf, 'p':params, 'rp': rparams})
                elif ty == "Event":
                    opcode = []
                    params = dict()
                    cur = ty
                    name = form[1][0].strip().replace('-', '').replace('\n','').split('[')[0].strip()
                    for i in range(1, form.rows):
                        opcode.append([eval(form[i][1].strip().replace('\n',''))])
                    for i in range(1, form.rows):
                        pnames = [pname for pname in form[i][2].replace(']', '],').split(',') if pname != '']
                        opcode[i-1].append(len(pnames))
                        for pname in pnames:
                            pname = pname.strip().replace('\n','').replace('-', '')
                            params[pname] = {'size': -1} if pname != '' else None
                    #params = list(map(lambda i: {'name': params[i]}, range(len(params))))
                    self.events.append({'name': name, 'opcode': opcode, 'p':params})
                elif cur == "Command":
                    pname, size = form.pname, form.size
                    if pname is not None:
                        if pname in self.commands[-1]['p'].keys() and self.commands[-1]['p'][pname]['size'] == -1:
                            self.commands[-1]['p'][pname]['size'] = size if size is not None else 0
                            self.commands[-1]['p'][pname]['domain'] = self.analyze_domain(form)
                        elif pname in self.commands[-1]['rp'].keys() and self.commands[-1]['rp'][pname]['size'] == -1:
                            self.commands[-1]['rp'][pname]['size'] = size if size is not None else 0
                            self.commands[-1]['rp'][pname]['domain'] = self.analyze_domain(form)
                elif cur == "Event":
                    pname, size = form.pname, form.size
                    if pname is not None:
                        if pname in self.events[-1]['p'].keys() and self.events[-1]['p'][pname]['size'] == -1:
                            self.events[-1]['p'][pname]['size'] = size if size is not None else 0
                            self.events[-1]['p'][pname]['domain'] = self.analyze_domain(form)
        self.command_names = [command['name'] for command in self.commands]



class HCIModelParser:
    def __init__(self, commands, events) -> None:
        self.parser = CoreNLPDependencyParser(SERVER_IP + ':' + SERVER_PORT)
        self.commands = commands
        self.events = events

    def normalize_names(self, norms, names):
        normalized_names = []
        for name in names:
            distance = [ Levenshtein.distance(norm['name'], name) for norm in norms ]
            i = distance.index(min(distance))
            normalized_names.append(norms[i]['name'])
        return normalized_names

    def get_entity_names(self, nodes, i):
        entities = []
        if 'compound' in nodes[i]['deps'].keys():
            j = nodes[i]['deps']['compound'][0]
            entities.append(nodes[j]['word'])
            if 'conj' in nodes[j]['deps']:
                for k in nodes[j]['deps']['conj']:
                    entities.append(nodes[k]['word'])
        elif 'amod' in nodes[i]['deps'].keys():
            j = nodes[i]['deps']['amod'][0]
            if '_' in nodes[j]['word']:
                entities.append(nodes[j]['word'])
        return entities


    def get_hci_entities(self, nodes, i, typename):
        entities = []
        neg = False
        workList = [i]
        while len(workList) > 0:
            cur = workList.pop(0)
            node = nodes[cur]
            if node['word'] == typename:
                entities += self.get_entity_names(nodes, cur)
            if 'neg' in node['deps']:
                neg = True
            for key, value in node['deps'].items():
                if key != 'advcl':
                    for dep in value:
                        workList.append(dep)
        if typename == 'command':
            entities = self.normalize_names(self.commands, entities)
        else:
            entities = self.normalize_names(self.events, entities)
        return entities, neg
    
    def print_ca_rules(self, 
                       commands_a, commands_neg_a,
                       events_a, events_neg_a,
                       commands_c, commands_neg_c, 
                       events_c, events_neg_c):
        for command_c in commands_c:
            cond1 = '' if not commands_neg_c else 'NOT'
            for event_a in events_a:
                cond2 = '' if not events_neg_a else 'NOT'
                print('IF {} {} then {} {}'.format(cond1, command_c, cond2, event_a))
            for command_a in commands_a:
                cond2 = '' if not commands_neg_a else 'NOT'
                print('IF {} {} then {} {}'.format(cond1, command_c, cond2, command_a))
    
        for event_c in events_c:
            cond1 = '' if not events_neg_c else 'NOT'
            for event_a in events_a:
                cond2 = '' if not events_neg_a else 'NOT'
                print('IF {} {} then {} {}'.format(cond1, event_c, cond2, event_a))
            for command_a in commands_a:
                cond2 = '' if not commands_neg_a else 'NOT'
                print('IF {} {} then {} {}'.format(cond1, event_c, cond2, command_a))



    def parse_event_desc(self, sent):
        sent_text = nltk.sent_tokenize(sent)
        sent_parses = self.parser.raw_parse_sents(sentences=sent_text)
        for i, sent_parse in enumerate(sent_parses):
            g = next(sent_parse)
            # open('a.dot', 'w').write(g.to_dot())
            # return
            nodes = g.nodes
            n = len(nodes)

            for i in range(n):
                if 'advcl' in nodes[i]['deps'].keys():
                    a ,c = i, nodes[i]['deps']['advcl'][0]
                    commands_a, commands_neg_a = self.get_hci_entities(nodes, a, 'command')
                    events_a, events_neg_a = self.get_hci_entities(nodes, a, 'event')
                    commands_c, commands_neg_c = self.get_hci_entities(nodes, c, 'command')
                    events_c, events_neg_c = self.get_hci_entities(nodes, c, 'event')
                    self.print_ca_rules(commands_a, commands_neg_a,
                                        events_a, events_neg_a,
                                        commands_c, commands_neg_c,
                                        events_c, events_neg_c)
                    return
            

            




sent = "If the connection is already established by the Baseband, but the BR/EDR Controller has not yet sent the HCI_Connection_Complete event, then the local device shall detach the link and return an HCI_Command_Complete event with the status “Success”."

hci = json.loads(open('hci.json', 'r').read())
parser = HCIModelParser(hci['commands'], hci['events'])
for command in parser.commands:
    parser.parse_event_desc(command['desc'])
exit(1)


ha = HCIAnalyzer("Core_v5.3.pdf", 1846, 2650)
ha.analyze()
ha.analyze_data()
ha.analyze_model()
# pprint.pprint(ha.commands, sort_dicts=False)
# with open("hci.json", 'w') as f:
#     f.write(json.dumps({"commands": ha.commands, "events": ha.events}, indent=2))
# pprint.pprint(ha.events, sort_dicts=False)
