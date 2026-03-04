import agent.bootstrap
import agent.patch_state
import riskengine.main
import riskengine.config 
import ai.state_checker
import ai.priority_recommender
import ai.mitigation_generator
import data.db_writer
import logging.logger

# services/scan_orchestrator.py
class ScanOrchestrator:
    def __init__(self, statechecker, , risk_engine, db_writer, mitigations):
         self.statechecker = statechecker
         self.risk_engine = risk_engine
         self.db_writer = db_writer
         self.mitigations = mitigations

    def execute_scan(self) -> dict:
         system = self.statechecker.run_orchestrator()
         findings = self.collect(system)
         scored = self.risk_engine.score(findings, system)
         summary = self.risk_engine.aggregate(scored, system)
         self.db_writer.persist_scan(system, scored, summary)
         return {"system": system, "findings": scored, "summary": summary}
    
    def state_check(self, findings: list) -> list:
         checked_findings = []
         for f in findings:
              c = self.statechecker.check(f)
              checked_findings.append(c)
         return checked_findings
    
    def generate_mitigations(self, findings: list) -> list:
         mitigations = []
         for f in findings:
              m = self.mitigations.generate(f)
              mitigations.append(m)
         return mitigations
    
    def recommend_priorities(self, findings: list) -> list:
         priorities = []
         for f in findings:
              p = self.priority_recommender.recommend(f)
              priorities.append(p)
         return priorities
    
    def run(self):
         logging.info("Starting scan orchestration")
         scan_results = self.execute_scan()
         mitigations = self.generate_mitigations(scan_results["findings"])
         priorities = self.recommend_priorities(scan_results["findings"])
         logging.info("Scan orchestration completed")
         return {
              "scan_results": scan_results,
              "mitigations": mitigations,
              "priorities": priorities
         }
