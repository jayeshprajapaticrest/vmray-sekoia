from vmray_modules.get_analysis_details_action import GetAnalysisDetails
from vmray_modules.get_quota_action import GetQuota
from vmray_modules.get_report_pdf_action import GetReportPdf
from vmray_modules.get_sample_action import GetSample
from vmray_modules.iocs_to_indicators_action import IocsToIndicators
from vmray_modules.models import VMRayModule
from vmray_modules.render_summary_action import RenderSummary
from vmray_modules.search_sample_action import SearchSample
from vmray_modules.submit_and_enrich_action import SubmitAndEnrich
from vmray_modules.submit_and_wait_action import SubmitAndWait
from vmray_modules.submit_file_action import SubmitFile
from vmray_modules.submit_url_action import SubmitUrl

if __name__ == "__main__":
    module = VMRayModule()
    module.register(IocsToIndicators, "IocsToIndicators")
    module.register(SubmitAndEnrich, "SubmitAndEnrich")
    module.register(SubmitAndWait, "SubmitAndWait")
    module.register(GetAnalysisDetails, "GetAnalysisDetails")
    module.register(GetReportPdf, "GetReportPdf")
    module.register(SearchSample, "SearchSample")
    module.register(SubmitUrl, "SubmitUrl")
    module.register(SubmitFile, "SubmitFile")
    module.register(RenderSummary, "RenderSummary")
    module.register(GetQuota, "GetQuota")
    module.register(GetSample, "GetSample")
    module.run()
