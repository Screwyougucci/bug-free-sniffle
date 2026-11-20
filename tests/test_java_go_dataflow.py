import tempfile
import unittest
from pathlib import Path
from darthscanner.analysis_graph import AnalysisGraph
from darthscanner.graph_adapters import build_project_graph
from darthscanner.java_go_dataflow import enrich_java_go_dataflow

class JavaGoDataflowTests(unittest.TestCase):
    def test_java_parameter_to_query_sink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"App.java"; p.write_text("class App { void find(String input) { db.query(input); } }",encoding="utf-8")
            g=AnalysisGraph(); enrich_java_go_dataflow(p,g,display_path="App.java")
            self.assertTrue(any(e.kind=="parameter-to-sink" for e in g.edges))
    def test_go_parameter_to_exec_sink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"app.go"; p.write_text("package main\nfunc run(input string) { exec(input) }",encoding="utf-8")
            g=AnalysisGraph(); enrich_java_go_dataflow(p,g,display_path="app.go")
            self.assertTrue(any(e.kind=="parameter-to-sink" for e in g.edges))
    def test_local_java_call_links_parameters(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"App.java"; p.write_text("class App { void sink(String value) { db.query(value); } void caller(String input) { sink(input); } }",encoding="utf-8")
            g=build_project_graph(d)
            self.assertTrue(any(e.kind=="call-argument" for e in g.edges))
            self.assertTrue(any(e.kind=="parameter-to-sink" for e in g.edges))
    def test_non_java_go_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"app.py"; p.write_text("print('safe')",encoding="utf-8")
            self.assertEqual(enrich_java_go_dataflow(p,AnalysisGraph()),0)

if __name__=="__main__":unittest.main()
