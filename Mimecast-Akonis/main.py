from mimecast_modules import MimecastModule
from mimecast_modules.actions.action_block_sender import MimecastBlockSender
from mimecast_modules.actions.action_decode_url import MimecastDecodeURL
from mimecast_modules.actions.action_delete_blocked_sender_policy import MimecastDeleteBlockedSenderPolicy
from mimecast_modules.actions.action_delete_managed_senders import MimecastDeleteManagedSenders
from mimecast_modules.actions.action_get_blocked_sender_policies import MimecastGetBlockedSenderPolicies
from mimecast_modules.actions.action_get_message_info import MimecastGetMessageInfo
from mimecast_modules.actions.action_get_reported_emails import MimecastGetReportedEmails
from mimecast_modules.actions.action_get_stats_attachment_scans import MimecastGetStatsAttachmentScans
from mimecast_modules.actions.action_get_stats_gateway_detections import MimecastGetStatsGatewayDetections
from mimecast_modules.actions.action_get_stats_impersonations import MimecastGetStatsImpersonations
from mimecast_modules.actions.action_get_stats_url_clicks import MimecastGetStatsURLClicks
from mimecast_modules.actions.action_get_threat_event_details import MimecastGetThreatEventDetails
from mimecast_modules.actions.action_get_threat_events import MimecastGetThreatEvents
from mimecast_modules.actions.action_get_threat_reports import MimecastGetThreatReports
from mimecast_modules.actions.action_get_threats_by_recipient import MimecastGetThreatsByRecipient
from mimecast_modules.actions.action_get_threats_by_sender import MimecastGetThreatsBySender
from mimecast_modules.actions.action_permit_sender import MimecastPermitSender
from mimecast_modules.actions.action_search_message import MimecastSearchMessage
from mimecast_modules.connector import MimecastConnector

if __name__ == "__main__":
    module = MimecastModule()
    module.register(MimecastConnector, "mimecast_siem_connector")
    module.register(MimecastBlockSender, "block_sender")
    module.register(MimecastPermitSender, "permit_sender")
    module.register(MimecastDeleteManagedSenders, "delete_managed_senders")
    module.register(MimecastDecodeURL, "decode_url")
    module.register(MimecastSearchMessage, "search_message")
    module.register(MimecastGetMessageInfo, "get_message_info")
    module.register(MimecastGetBlockedSenderPolicies, "get_blocked_sender_policies")
    module.register(MimecastDeleteBlockedSenderPolicy, "delete_blocked_sender_policy")
    module.register(MimecastGetThreatEvents, "get_threat_events")
    module.register(MimecastGetThreatEventDetails, "get_threat_event_details")
    module.register(MimecastGetStatsAttachmentScans, "get_stats_attachment_scans")
    module.register(MimecastGetStatsGatewayDetections, "get_stats_gateway_detections")
    module.register(MimecastGetStatsURLClicks, "get_stats_url_clicks")
    module.register(MimecastGetStatsImpersonations, "get_stats_impersonations")
    module.register(MimecastGetThreatsBySender, "get_threats_by_sender")
    module.register(MimecastGetThreatsByRecipient, "get_threats_by_recipient")
    module.register(MimecastGetReportedEmails, "get_reported_emails")
    module.register(MimecastGetThreatReports, "get_threat_reports")
    module.run()
