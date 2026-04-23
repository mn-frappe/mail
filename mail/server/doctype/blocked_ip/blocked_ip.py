# Copyright (c) 2025, Frappe Technologies Pvt. Ltd. and contributors
# For license information, please see license.txt

import json

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import today

from mail.backend_adapter import get_management_backend_adapter
from mail.utils import extract_filter_values
from mail.utils.dns import get_host_by_ip


class BlockedIP(Document):
	@property
	def host(self) -> str | None:
		"""Returns the host name of the IP address."""

		if self.ip_address:
			return get_host_by_ip(self.ip_address)

	def autoname(self) -> None:
		self.name = f"{self.cluster}|{self.ip_address}"

	def db_insert(self, *args, **kwargs) -> None:
		self._create()

	def load_from_db(self) -> "BlockedIP":
		blocked_ip = self._get()
		return super(Document, self).__init__(blocked_ip)

	def db_update(self) -> None:
		self._update()

	def delete(self) -> None:
		self._delete()
		if not frappe.flags.in_bulk_delete:
			frappe.msgprint(_("Blocked IP removed successfully."), alert=True)

	@staticmethod
	def get_list(filters=None, page_length=20, **kwargs) -> list:
		filters = filters or []
		cluster, ip_address = extract_filter_values(filters, [{"cluster": "="}, {"ip_address": "like"}])

		if cluster:
			blocked_ips = BlockedIP._get_all(cluster, limit=page_length, text=ip_address)
			if not blocked_ips:
				frappe.msgprint(_("No blocked IPs found."), alert=True)

			return blocked_ips

		frappe.msgprint(_("Please select a cluster to view blocked IPs."), alert=True)
		return []

	@staticmethod
	def get_count(filters=None, **kwargs) -> int:
		filters = filters or []
		cluster, ip_address = extract_filter_values(filters, [{"cluster": "="}, {"ip_address": "like"}])

		return frappe.cache.get_value(get_total_cache_key(cluster, ip_address)) if cluster else 0

	@staticmethod
	def get_stats(**kwargs) -> dict:
		return {}

	def _create(self) -> None:
		"""Creates the blocked IP in the backend."""

		ip_addresses = [self.ip_address]
		request_data = []
		for ip in ip_addresses:
			request_data.append(
				{
					"type": "insert",
					"prefix": None,
					"values": [[f"server.blocked-ip.{ip}", ""]],
					"assert_empty": True,
				}
			)

		backend_api = get_management_backend_adapter()
		backend_api.settings_patch(request_data)

	def _get(self) -> None:
		"""Returns the blocked IP from the backend."""

		cluster, ip_address = self.name.split("|")
		backend_api = get_management_backend_adapter()
		response = backend_api.settings_group("server.blocked-ip")

		data = (response.data or {}).get("data", {})
		items = data.get("items", [])
		blocked_ip = next((item for item in items if item.get("_id") == ip_address), None)
		if not blocked_ip:
			frappe.throw(_("Blocked IP {0} not found.").format(ip_address))

		return BlockedIP._format(blocked_ip, cluster)

	@staticmethod
	def _get_all(cluster: str, page: int = 1, limit: int = 10, text: str | None = None) -> list:
		"""Returns all blocked IPs for the given cluster."""

		backend_api = get_management_backend_adapter()
		response = backend_api.settings_group("server.blocked-ip")

		data = (response.data or {}).get("data", {})
		items = data.get("items", [])
		if text:
			items = [item for item in items if text in item.get("_id", "")]

		start = max((page - 1) * limit, 0)
		end = start + limit
		page_items = items[start:end]

		frappe.cache.set_value(get_total_cache_key(cluster, text), len(items), expires_in_sec=600)

		return [BlockedIP._format(item, cluster) for item in page_items]

	def _update(self) -> None:
		raise NotImplementedError

	def _delete(self) -> None:
		"""Deletes the blocked IP from the backend."""

		ip_addresses = [self.ip_address]
		request_data = []
		for ip in ip_addresses:
			request_data.append({"type": "delete", "keys": [f"server.blocked-ip.{ip}"]})

		backend_api = get_management_backend_adapter()
		backend_api.settings_patch(request_data)

	@staticmethod
	def _format(blocked_ip: dict, cluster: str) -> dict:
		"""Formats the blocked IP data from the backend."""

		return {
			"cluster": cluster,
			"ip_address": blocked_ip["_id"],
			"name": f"{cluster}|{blocked_ip['_id']}",
			"creation": today(),
			"modified": today(),
		}


def get_total_cache_key(cluster: str, text: str | None = None) -> str:
	"""Returns a cache key for total blocked IP count."""

	text = text or ""
	return f"{cluster}:blocked-ip:{text}:total"
