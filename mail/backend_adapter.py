from dataclasses import dataclass
from typing import Any

import frappe
from frappe import _

from mail.backend import MailBackendAPI, get_mail_backend_api
from mail.jmap.connection import JMAPConnection, JMAPConnectionInfo
from mail.utils import get_mail_config


@dataclass
class ManagementResponse:
	"""Normalized response shape for backend management operations."""

	status_code: int
	data: Any


class ManagementBackendAdapter:
	"""Adapter layer to isolate management API protocol differences (REST vs JMAP)."""

	def __init__(
		self,
		mode: str | None = None,
		base_url: str | None = None,
		api_key: str | None = None,
		username: str | None = None,
		password: str | None = None,
	) -> None:
		config_mode = (get_mail_config("management_api_mode") or "").strip().lower()
		self.mode = (mode or config_mode or "rest").lower()
		self._rest = None
		if self.mode == "rest":
			if base_url and (api_key or (username and password)):
				self._rest = MailBackendAPI(
					base_url=base_url,
					api_key=api_key,
					username=username,
					password=password,
				)
			else:
				self._rest = get_mail_backend_api()
		self._jmap = self._init_jmap() if self.mode == "jmap" else None

	def principal_create(self, payload: dict) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("POST", "/api/principal", json=payload)

		response = self._jmap_method_call("Principal/set", {"create": {"new": payload}})
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		return ManagementResponse(status_code=200, data={"data": response})

	def principal_get(self, principal_id: str) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("GET", f"/api/principal/{principal_id}")

		response = self._jmap_method_call("Principal/get", {"ids": [principal_id]})
		if error := response.get("error"):
			if "notFound" in str(error):
				return ManagementResponse(status_code=404, data={"error": "notFound"})
			return ManagementResponse(status_code=400, data={"error": error})

		items = response.get("list", [])
		if not items:
			return ManagementResponse(status_code=404, data={"error": "notFound"})

		return ManagementResponse(status_code=200, data={"data": items[0]})

	def principal_list(self, params: dict | None = None) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("GET", "/api/principal", params=params)

		params = params or {}
		position = int(params.get("page", 1)) - 1
		limit = int(params.get("limit", 10))

		query_payload: dict[str, Any] = {
			"position": max(position, 0),
			"limit": max(limit, 1),
			"calculateTotal": True,
		}

		if filter_value := params.get("filter"):
			query_payload["filter"] = {"name": str(filter_value)}

		if ptype := params.get("types"):
			query_payload.setdefault("filter", {})
			query_payload["filter"]["type"] = ptype

		query_response = self._jmap_method_call("Principal/query", query_payload)
		if error := query_response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		ids = query_response.get("ids", [])
		total = query_response.get("total", len(ids))

		if not ids:
			return ManagementResponse(status_code=200, data={"data": {"items": [], "total": 0}})

		get_response = self._jmap_method_call("Principal/get", {"ids": ids})
		if error := get_response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		return ManagementResponse(
			status_code=200,
			data={"data": {"items": get_response.get("list", []), "total": total}},
		)

	def principal_update(self, principal_id: str, payload: dict) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("PATCH", f"/api/principal/{principal_id}", json=payload)

		# Convert legacy action list to JMAP update patch object.
		patch: dict[str, Any] = {}
		actions = payload if isinstance(payload, list) else payload.get("actions", [])
		for action in actions:
			atype = action.get("action")
			field = action.get("field")
			value = action.get("value")
			if atype == "set":
				patch[field] = value
			elif atype == "addItem":
				patch[f"{field}/+"] = value
			elif atype == "removeItem":
				patch[f"{field}/-"] = value

		response = self._jmap_method_call("Principal/set", {"update": {principal_id: patch}})
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		if response.get("notUpdated"):
			return ManagementResponse(status_code=400, data={"error": response["notUpdated"]})

		return ManagementResponse(status_code=200, data={"data": response})

	def principal_delete(self, principal_id: str) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("DELETE", f"/api/principal/{principal_id}")

		response = self._jmap_method_call("Principal/set", {"destroy": [principal_id]})
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		if response.get("notDestroyed"):
			return ManagementResponse(status_code=400, data={"error": response["notDestroyed"]})

		return ManagementResponse(status_code=200, data={"data": response})

	def dkim_create(self, payload: dict) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("POST", "/api/settings", data=payload)

		dkim_payload = self._build_dkim_payload(payload)
		response = self._jmap_method_call_any(
			["DkimSignature/set", "x:DkimSignature/set"],
			{"create": {"new": dkim_payload}},
		)
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		return ManagementResponse(status_code=200, data={"data": response})

	def dkim_delete(self, payload: dict) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("POST", "/api/settings", data=payload)

		domain_name, algorithm = self._extract_dkim_delete_hint(payload)
		if not domain_name:
			return ManagementResponse(status_code=400, data={"error": "Invalid DKIM delete payload."})

		query_filter: dict[str, Any] = {"domain": domain_name}
		if algorithm:
			query_filter["algorithm"] = algorithm

		query_response = self._jmap_method_call_any(
			["DkimSignature/query", "x:DkimSignature/query"],
			{"filter": query_filter, "limit": 100, "calculateTotal": False},
		)
		if error := query_response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		ids = query_response.get("ids", [])
		if not ids:
			return ManagementResponse(status_code=200, data={"data": {"destroyed": []}})

		response = self._jmap_method_call_any(
			["DkimSignature/set", "x:DkimSignature/set"],
			{"destroy": ids},
		)
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		return ManagementResponse(status_code=200, data={"data": response})

	def fetch_dns_records(self, domain_name: str) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("GET", f"/api/dns/records/{domain_name}")

		response = self._jmap_method_call_any(
			["Domain/get", "x:Domain/get"],
			{"ids": [domain_name], "properties": ["dnsRecords"]},
		)
		if error := response.get("error"):
			if "notFound" in str(error):
				return ManagementResponse(status_code=404, data={"error": "notFound"})
			return ManagementResponse(status_code=400, data={"error": error})

		items = response.get("list", [])
		if not items:
			return ManagementResponse(status_code=404, data={"error": "notFound"})

		return ManagementResponse(status_code=200, data={"data": items[0].get("dnsRecords", [])})

	def dmarc_report_list(self, params: dict | None = None) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("GET", "/api/reports/dmarc", params=params)

		params = params or {}
		position = int(params.get("page", 1)) - 1
		limit = int(params.get("limit", 10))

		payload: dict[str, Any] = {
			"position": max(position, 0),
			"limit": max(limit, 1),
			"calculateTotal": True,
		}

		if filter_value := params.get("filter"):
			payload["filter"] = {"text": str(filter_value)}

		response = self._jmap_method_call_any(
			["DmarcReport/query", "x:DmarcReport/query"],
			payload,
		)
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		return ManagementResponse(
			status_code=200,
			data={
				"data": {
					"items": response.get("ids", []),
					"total": response.get("total", 0),
				}
			},
		)

	def dmarc_report_get(self, report_id: str) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("GET", f"/api/reports/dmarc/{report_id}")

		response = self._jmap_method_call_any(
			["DmarcReport/get", "x:DmarcReport/get"],
			{"ids": [report_id]},
		)
		if error := response.get("error"):
			if "notFound" in str(error):
				return ManagementResponse(status_code=404, data={"error": "notFound"})
			return ManagementResponse(status_code=400, data={"error": error})

		items = response.get("list", [])
		if not items:
			return ManagementResponse(status_code=404, data={"error": "notFound"})

		return ManagementResponse(status_code=200, data={"data": items[0]})

	def dmarc_report_delete(self, report_id: str) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("DELETE", f"/api/reports/dmarc/{report_id}")

		response = self._jmap_method_call_any(
			["DmarcReport/set", "x:DmarcReport/set"],
			{"destroy": [report_id]},
		)
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		if response.get("notDestroyed"):
			return ManagementResponse(status_code=400, data={"error": response["notDestroyed"]})

		return ManagementResponse(status_code=200, data={"data": response})

	def queue_messages_list(self, params: dict | None = None) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("GET", "/api/queue/messages", params=params)

		params = params or {}
		position = int(params.get("page", 1)) - 1
		limit = int(params.get("limit", 10))

		payload: dict[str, Any] = {
			"position": max(position, 0),
			"limit": max(limit, 1),
			"calculateTotal": True,
		}

		if text := params.get("text"):
			payload["filter"] = {"text": str(text)}

		query_response = self._jmap_method_call_any(
			["MessageQueue/query", "x:MessageQueue/query"],
			payload,
		)
		if error := query_response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		ids = query_response.get("ids", [])
		total = query_response.get("total", len(ids))
		status = query_response.get("status", "running")

		if not ids:
			return ManagementResponse(
				status_code=200,
				data={"data": {"items": [], "total": total, "status": status}},
			)

		get_response = self._jmap_method_call_any(
			["MessageQueue/get", "x:MessageQueue/get"],
			{"ids": ids},
		)
		if error := get_response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		return ManagementResponse(
			status_code=200,
			data={
				"data": {
					"items": get_response.get("list", []),
					"total": total,
					"status": status,
				}
			},
		)

	def queue_message_get(self, message_id: str) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("GET", f"/api/queue/messages/{message_id}")

		response = self._jmap_method_call_any(
			["MessageQueue/get", "x:MessageQueue/get"],
			{"ids": [message_id]},
		)
		if error := response.get("error"):
			if "notFound" in str(error):
				return ManagementResponse(status_code=404, data={"error": "notFound"})
			return ManagementResponse(status_code=400, data={"error": error})

		items = response.get("list", [])
		if not items:
			return ManagementResponse(status_code=404, data={"error": "notFound"})

		return ManagementResponse(status_code=200, data={"data": items[0]})

	def queue_message_retry(self, message_id: str, payload: dict | None = None) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("PATCH", f"/api/queue/messages/{message_id}", json=payload or {})

		response = self._jmap_method_call_any(
			["MessageQueue/set", "x:MessageQueue/set"],
			{"update": {message_id: {"action": "retry", **(payload or {})}}},
		)
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		if response.get("notUpdated"):
			return ManagementResponse(status_code=400, data={"error": response["notUpdated"]})

		return ManagementResponse(status_code=200, data={"data": response})

	def queue_message_cancel(self, message_id: str, recipient: str | None = None) -> ManagementResponse:
		if self.mode == "rest":
			params = {"filter": recipient} if recipient else None
			return self._rest_json("DELETE", f"/api/queue/messages/{message_id}", params=params)

		if recipient:
			response = self._jmap_method_call_any(
				["MessageQueue/set", "x:MessageQueue/set"],
				{"update": {message_id: {"action": "cancel", "recipient": recipient}}},
			)
			if error := response.get("error"):
				return ManagementResponse(status_code=400, data={"error": error})
			if response.get("notUpdated"):
				return ManagementResponse(status_code=400, data={"error": response["notUpdated"]})
			return ManagementResponse(status_code=200, data={"data": response})

		response = self._jmap_method_call_any(
			["MessageQueue/set", "x:MessageQueue/set"],
			{"destroy": [message_id]},
		)
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		if response.get("notDestroyed"):
			return ManagementResponse(status_code=400, data={"error": response["notDestroyed"]})

		return ManagementResponse(status_code=200, data={"data": response})

	def queue_status_start(self) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("PATCH", "/api/queue/status/start")

		response = self._jmap_method_call_any(
			["QueueSettings/set", "x:QueueSettings/set", "SystemSettings/set", "x:SystemSettings/set"],
			{"update": {"singleton": {"status": "running"}}},
		)
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		return ManagementResponse(status_code=200, data={"data": response})

	def queue_status_stop(self) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("PATCH", "/api/queue/status/stop")

		response = self._jmap_method_call_any(
			["QueueSettings/set", "x:QueueSettings/set", "SystemSettings/set", "x:SystemSettings/set"],
			{"update": {"singleton": {"status": "stopped"}}},
		)
		if error := response.get("error"):
			return ManagementResponse(status_code=400, data={"error": error})

		return ManagementResponse(status_code=200, data={"data": response})

	def blob_get(self, blob_id: str) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_bytes("GET", f"/api/store/blobs/{blob_id}")

		account_id = self._jmap_blob_account_id()
		if not account_id:
			return ManagementResponse(status_code=400, data={"error": "No JMAP account available."})

		download_url = self._jmap.download_url.format(
			accountId=account_id,
			blobId=blob_id,
			name="message.eml",
			type="message/rfc822",
		)

		blob_bytes = self._jmap.request(method="GET", url=download_url, return_json=False)
		return ManagementResponse(status_code=200, data=blob_bytes)

	def settings_patch(self, payload: dict) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("POST", "/api/settings", json=payload)
		return self._jmap_not_implemented("System settings migration required")

	def settings_group(self, prefix: str) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("GET", "api/settings/group", params={"prefix": prefix})
		return self._jmap_not_implemented("System settings migration required")

	def reload(self) -> ManagementResponse:
		if self.mode == "rest":
			return self._rest_json("GET", "/api/reload")
		# JMAP management applies changes immediately.
		return ManagementResponse(status_code=200, data={"data": None})

	def _rest_json(self, method: str, endpoint: str, **kwargs) -> ManagementResponse:
		response = self._rest.request(method, endpoint, **kwargs)
		data = None
		if response.text:
			data = response.json()
		return ManagementResponse(status_code=response.status_code, data=data)

	def _rest_bytes(self, method: str, endpoint: str, **kwargs) -> ManagementResponse:
		response = self._rest.request(method, endpoint, **kwargs)
		return ManagementResponse(status_code=response.status_code, data=response.content)

	def _init_jmap(self) -> JMAPConnection:
		config = get_mail_config()
		username = config.get("username")
		password = config.get("password")
		server_url = config.get("server_url")

		if not (server_url and username and password):
			frappe.throw(_("JMAP mode requires server URL, username and password in Mail Settings."))

		return JMAPConnection(JMAPConnectionInfo(url=server_url, username=username, password=password))

	def _jmap_using_capabilities(self) -> list[str]:
		capabilities = list(self._jmap.capabilities.keys())
		if "urn:ietf:params:jmap:core" not in capabilities:
			capabilities.insert(0, "urn:ietf:params:jmap:core")
		return capabilities

	def _jmap_account_id(self) -> str:
		if principals_account := self._jmap.primary_accounts.get("urn:ietf:params:jmap:principals"):
			return principals_account

		if self._jmap.accounts:
			return list(self._jmap.accounts.keys())[0]

		return ""

	def _jmap_blob_account_id(self) -> str:
		for capability in [
			"urn:ietf:params:jmap:blob",
			"urn:ietf:params:jmap:mail",
			"urn:ietf:params:jmap:principals",
		]:
			if account_id := self._jmap.primary_accounts.get(capability):
				return account_id

		if self._jmap.accounts:
			return list(self._jmap.accounts.keys())[0]

		return ""

	def _jmap_method_call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
		if "accountId" not in payload:
			payload["accountId"] = self._jmap_account_id()

		response = self._jmap.request(
			method="POST",
			url=self._jmap.api_url,
			headers={"Content-Type": "application/json"},
			json={
				"using": self._jmap_using_capabilities(),
				"methodCalls": [[method, payload, "0"]],
			},
		)

		method_responses = response.get("methodResponses", [])
		if not method_responses:
			return {"error": "Empty methodResponses from JMAP backend."}

		method_name, data, _call_id = method_responses[0]
		if method_name == "error":
			return {"error": data}

		return data

	def _jmap_method_call_any(self, methods: list[str], payload: dict[str, Any]) -> dict[str, Any]:
		last_error: Any = None
		for method in methods:
			response = self._jmap_method_call(method, dict(payload))
			error = response.get("error")
			if not error:
				return response

			error_type = str(error.get("type", "")) if isinstance(error, dict) else str(error)
			if "unknownMethod" in error_type:
				last_error = error
				continue

			if "forbidden" in error_type:
				return {
					"error": {
						"type": "forbidden",
						"description": (
							"JMAP management method is forbidden for this account. "
							"Complete bootstrap setup and use a provisioned admin account."
						),
						"details": error,
					}
				}

			return response

		return {
			"error": {
				"type": "unknownMethod",
				"description": f"No supported method found in candidates: {', '.join(methods)}",
				"details": last_error,
			}
		}

	def _build_dkim_payload(self, payload: Any) -> dict[str, Any]:
		if not isinstance(payload, list) or not payload:
			return {}

		entry = payload[0]
		values = dict(entry.get("values") or [])
		prefix = entry.get("prefix", "")
		domain_name = values.get("domain")
		if not domain_name and prefix.startswith("signature."):
			domain_name = prefix.split("-", 1)[-1]

		return {
			"domain": domain_name,
			"selector": values.get("selector"),
			"algorithm": values.get("algorithm"),
			"privateKey": values.get("private-key"),
			"canonicalization": values.get("canonicalization"),
			"report": values.get("report") in [True, "true", "1", 1],
		}

	def _extract_dkim_delete_hint(self, payload: Any) -> tuple[str | None, str | None]:
		if not isinstance(payload, list) or not payload:
			return None, None

		entry = payload[0]
		prefix = entry.get("prefix", "")
		if not prefix.startswith("signature."):
			return None, None

		value = prefix.removeprefix("signature.")
		if "-" not in value:
			return None, None

		key_type, domain_name = value.split("-", 1)
		algorithm = f"{key_type}-sha256"
		return domain_name, algorithm

	def _jmap_not_implemented(self, method_hint: str) -> ManagementResponse:
		frappe.throw(_("JMAP management method not implemented yet: {0}").format(method_hint))


def get_management_backend_adapter(
	mode: str | None = None,
	base_url: str | None = None,
	api_key: str | None = None,
	username: str | None = None,
	password: str | None = None,
) -> ManagementBackendAdapter:
	"""Factory for management adapter used by server doctypes."""

	return ManagementBackendAdapter(
		mode=mode,
		base_url=base_url,
		api_key=api_key,
		username=username,
		password=password,
	)
