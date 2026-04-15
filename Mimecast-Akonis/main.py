from mimecast_modules import MimecastModule
from mimecast_modules.connector import MimecastConnector

if __name__ == "__main__":
    module = MimecastModule()
    module.register(MimecastConnector, "mimecast_siem_connector")
    module.run()
