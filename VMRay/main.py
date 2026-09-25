from vmray_modules.build_report_action import BuildReport
from vmray_modules.get_samples_by_hash_action import GetSamplesByHash
from vmray_modules.models import VMRayModule
from vmray_modules.render_report_action import RenderReport
from vmray_modules.report_to_indicators_action import ReportToIndicators
from vmray_modules.submit_url_sample_action import SubmitUrlSample

if __name__ == "__main__":
    module = VMRayModule()
    module.register(BuildReport, "BuildReport")
    module.register(ReportToIndicators, "ReportToIndicators")
    module.register(SubmitUrlSample, "SubmitUrlSample")
    module.register(GetSamplesByHash, "GetSamplesByHash")
    module.register(RenderReport, "RenderReport")
    module.run()
