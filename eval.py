import requests
from concurrent.futures import ThreadPoolExecutor
import pem
#from io import StringIO
import shutil



class TrustedBundle:
    def __init__(self, trust_bundle_path):
        self.trust_bundle_path = trust_bundle_path

        # adjustments
        self.timeout = 20

        # stats
        self.all_requests = 0
        self.validation_success = 0
        self.validation_failed = 0
        self.error = 0

    def validate_request(self, url):
        self.all_requests += 1
        try:
            print(url)
            requests.get(url, timeout=self.timeout, verify=self.trust_bundle_path)
            self.validation_success += 1
        except requests.exceptions.SSLError as e:
            self.validation_failed += 1
            return
        #except requests.exceptions.ConnectionError as e:
        #    pass
        except Exception as e:
            self.error += 1
            return

    def __str__(self):
        return f"""
            trust_bundle_path: {self.trust_bundle_path}
            all_requests: {self.all_requests}
            validation_success: {self.validation_success}
            validation_failed: {self.validation_failed}
            error: {self.error}
        """


class BundleFiles:
    def __init__(self, full_bundle_path, bundle_rules):
        self.full_bundle_path = full_bundle_path

        # rule e.g. "top:10", "mozilla-2020-10-14.pem:-1", "all"
        # ("top:1", "top:3", "top:5", "top:10", "top:20", "top:30", "all:-1", "mozilla-2020-10-14.pem:-1")
        self.bundle_rules = bundle_rules

        self.bundle_paths = []

        self._create_bundles()

    def _create_bundles(self):
        full_bundle_parsed = pem.parse_file(self.full_bundle_path)

        for bundle_rule in self.bundle_rules:
            rule, number = bundle_rule.split(":")
            result_file_path = f"{rule}-{number}.pem"
            number = int(number)

            with open(result_file_path, "w") as result_file:
                if rule == "top":
                    for i in range(number):
                        if i > (len(full_bundle_parsed) - 1):
                            raise Exception(f"Rule {bundle_rule} out of bounce.")
                        result_file.write(
                            str(full_bundle_parsed[i]).replace("\r\n", "\n"))
                        result_file.write("\n\n")
                elif rule == "all":
                    shutil.copy(src=self.full_bundle_path, dst=result_file_path)
                else:
                    shutil.copy(src=rule, dst=result_file_path)

            self.bundle_paths.append(result_file_path)


class Run:
    def __init__(self, run_name, condition, bundle_files):
        self.run_name = run_name
        self.condition = condition

        self.trusted_bundles = [
            TrustedBundle(trust_bundle_path=bundle_path)
            for bundle_path in bundle_files.bundle_paths]

    def run(self):
        with open("top-1m.csv", "r") as f, ThreadPoolExecutor() as executor:
            for line in f:
                number, url = line.split(",")
                url = "https://" + url.strip()

                # abort condition
                condition = self.condition(number, url)
                if condition == "pass":
                    pass
                elif condition == "break":
                    break
                elif condition == "continue":
                    continue

                for bundle in self.trusted_bundles:
                    executor.submit(bundle.validate_request, url=url)

    def result(self):
        for bundle in self.trusted_bundles:
            print(str(bundle))


TestBundleFiles = BundleFiles(
    full_bundle_path="user_bundle.pem",
    bundle_rules=("top:1", "top:3", "top:5", "top:10",
                  "top:20", "all:-1", "mozilla-2020-10-14.pem:-1")
)


def top2000_condition(number, url):
    if int(number) > 2000:
        return "break"
    return "pass"

Top2000Run = Run(
    run_name="top2000",
    condition=top2000_condition,
    bundle_files=TestBundleFiles
)

Top2000Run.run()
Top2000Run.result()


def bottom2000_condition(number, url):
    if int(number) < 728714:
        return "continue"
    return "pass"

Bottom2000Run = Run(
    run_name="bottom2000",
    condition=bottom2000_condition,
    bundle_files=TestBundleFiles
)

Bottom2000Run.run()
Bottom2000Run.result()