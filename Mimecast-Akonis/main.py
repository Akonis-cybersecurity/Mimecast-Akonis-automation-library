from mimecast_modules import MimecastModule
from mimecast_modules.account_validator import MimecastAccountValidator
from mimecast_modules.connector import MimecastConnector

if __name__ == "__main__":
    module = MimecastModule()
    module.register_account_validator(MimecastAccountValidator)
    module.register(MimecastConnector, "mimecast_siem_connector")
    module.run()
