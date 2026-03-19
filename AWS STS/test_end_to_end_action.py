from pathlib import Path

from microsoft_ad.models.action_models import UserAccountArguments
from microsoft_ad.models.common_models import MicrosoftADConfiguration
from microsoft_ad.user_actions import DisableUserAction

if __name__ == "__main__":
    current_path: Path = Path("/test_data")
    module_configuration: MicrosoftADConfiguration = MicrosoftADConfiguration(
        servername="20.238.27.101",
        admin_username="integration@integration.local",
        admin_password="sekoia2026!!2026",
    )

    user_account_arguments = UserAccountArguments(
        basedn="CN=Users,DC=integration,DC=local",
        email="test.integration@integration.local",
        apply_to_all=True,
    )

    action = DisableUserAction()
    action.module.configuration = module_configuration
    action.run(user_account_arguments)
