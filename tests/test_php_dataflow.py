import tempfile
import unittest
from pathlib import Path
from darthscanner.analysis_graph import AnalysisGraph
from darthscanner.graph_adapters import build_project_graph
from darthscanner.php_dataflow import enrich_php_dataflow

class PhpDataflowTests(unittest.TestCase):
    def test_parameter_reaches_sql_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"app.php"
            path.write_text("<?php\nfunction findUser($db,$value) {\n $db->query($value);\n}\n",encoding="utf-8")
            graph=AnalysisGraph()
            enrich_php_dataflow(path,graph,display_path="app.php")
            self.assertTrue(any(edge.kind=="parameter-to-sink" for edge in graph.edges))
    def test_local_call_argument_is_linked(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"app.php"
            path.write_text("<?php\nfunction findUser($db,$value) {\n $db->query($value);\n}\nfunction handler($db,$input) {\n findUser($db,$input);\n}\n",encoding="utf-8")
            graph=build_project_graph(directory)
            self.assertTrue(any(edge.kind=="call-argument" for edge in graph.edges))
            self.assertTrue(any(edge.kind=="parameter-to-sink" for edge in graph.edges))
    def test_external_call_is_not_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"app.php"
            path.write_text("<?php function handler($value) { thirdParty($value); }",encoding="utf-8")
            graph=AnalysisGraph()
            enrich_php_dataflow(path,graph,display_path="app.php")
            self.assertFalse(any(edge.kind=="call-argument" for edge in graph.edges))
if __name__=="__main__": unittest.main()
