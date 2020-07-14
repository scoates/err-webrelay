import hmac
import hashlib

from errbot import BotPlugin, webhook, ValidationException
from flask import abort


class WebRelay(BotPlugin):
    """
    Relays information from HTTP POST to IRC
    """

    def get_configuration_template(self):
        return {
            "CLIENT_SECRET": "f9876",
        }

    def activate(self):
        if not self.config:
            self.log.info("Not configured. Forbidding activation.")
            return
        super().activate()

    def _has_valid_sig(self, request):
        data = request.stream.read()
        sig = request.headers.get("Post-Signature")

        if sig is None:
            self.log.debug("No signature")
            return False

        digest = hmac.new(
            key=self.config["CLIENT_SECRET"].encode("utf-8"),
            msg=data,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if digest != sig:
            self.log.debug("Invalid signature.")
            return False

        self.log.debug("Valid signature.")
        return data

    @webhook("/relay/<channel>", raw=True)
    def web_notification(self, request, channel):

        message = self._has_valid_sig(request)
        if not message:
            self.log.warn("Invalid signature.")
            abort(403)

        channel = f"#{channel}"
        found_channel = False
        for room in self.rooms():
            if room.room == channel:
                found_channel = True
                break
        if not found_channel:
            self.log.warn("Can't relay to non-present channels.")
            abort(404)

        self.log.info(f"Relaying to {channel}")
        target = self.build_identifier(channel)

        if not isinstance(message, str):
            message = message.decode()
        self.send(
            target,
            f"({self._color_string('red', 'web')}) {self._color_string('cyan', message)}",
        )
        return f"Message relayed to {target}", 202

    @staticmethod
    def _color_string(color, string):
        return "`" + string + "`{:color='" + color + "'}"
