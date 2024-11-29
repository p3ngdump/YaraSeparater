import yara

STORAGE_PATH = "yara_rules"
EXT = ".yar"

class YaraSeparater:
    def __init__(self, rule_path):
        self.rule_path = rule_path
        self.separate_keyword = "rule"

    def cut_yara(self):
        with open(self.rule_path, "r") as f:
            total_yara_rules = f.read()

        yara_rules = total_yara_rules.split(self.separate_keyword)
        for yara_rule in yara_rules:
            yara_title = yara_rule.split(" ")[1]
            yara_content = self.separate_keyword + yara_rule

            test_result = self.test_yara(yara_content)
            if test_result != "Yara Test Success":
                print(f"{yara_title} is not valid yara rule.")
                continue

            result = self.save_yara(yara_title, yara_content)
            if result == "Yara Save Success":
                print(f"{yara_title} is saved.")
            else:
                print(f"{yara_title} is not saved.")

        return "Yara Cut Success"

    def save_yara(self, yara_title, yara_content):
        try:
            with open(f"{STORAGE_PATH}/{yara_title}{EXT}", "w") as f:
                f.write(yara_content)

            return "Yara Save Success"
        except Exception as e:
            raise e

    def test_yara(self, yara_rule):
        try:
            rule = yara.compile(sources={yara_rule})
            return "Yara Test Success"
        except Exception as e:
            return e

if __name__ == "__main__":
    yara_cutter = YaraSeparater("yara_rules.yar")
    yara_cutter.cut_yara()
