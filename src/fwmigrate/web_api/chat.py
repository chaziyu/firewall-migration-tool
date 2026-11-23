"""HTTP endpoints for the floating AI configuration assistant (/api/chat)."""

from __future__ import annotations

from hashlib import sha256

from flask import jsonify, make_response, request

from fwmigrate.web_support.chat_service import (
    ask_gemini,
    build_config_summary,
    chat_store,
    detect_vendor_from_content,
    get_api_key_status,
)
from fwmigrate.web_support.request_controls import live_device_access_allowed

_SESSION_COOKIE = "fwmigrate_chat_sid"


def _attach_cookie(response, session_id: str, created: bool) -> None:
    if created:
        response.set_cookie(
            _SESSION_COOKIE,
            session_id,
            httponly=True,
            samesite="Lax",
            secure=request.is_secure,
            path="/",
        )


def _mismatch_message(sess) -> str | None:
    if sess.vendor_mismatch and sess.vendor and sess.vendor_mismatch != sess.vendor:
        return f"Note: Selected vendor indicated {sess.vendor}, while configuration content looks like {sess.vendor_mismatch}."
    return None


def register_chat_routes(app) -> None:
    @app.route("/api/chat", methods=["GET"])
    def chat_state():
        allow_env = live_device_access_allowed(app)
        sess = chat_store.get(request.cookies.get(_SESSION_COOKIE))
        if sess is None:
            return jsonify({
                "history": [],
                "vendor_mismatch": None,
                "key_status": get_api_key_status(None, allow_env_fallback=allow_env),
            })
        return jsonify({
            "history": sess.chat_history,
            "vendor_mismatch": _mismatch_message(sess),
            "key_status": get_api_key_status(sess.gemini_api_key, allow_env_fallback=allow_env),
        })

    @app.route("/api/chat/key", methods=["POST"])
    def chat_set_key():
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Request body must be a JSON object."}), 400
        allow_env = live_device_access_allowed(app)
        sess, created = chat_store.get_or_create(request.cookies.get(_SESSION_COOKIE))
        cleaned = str(payload.get("api_key") or "").strip()
        sess.gemini_api_key = cleaned or None
        response = make_response(jsonify({
            "ok": True,
            "key_status": get_api_key_status(sess.gemini_api_key, allow_env_fallback=allow_env),
        }))
        _attach_cookie(response, sess.session_id, created)
        return response

    @app.route("/api/chat", methods=["POST"])
    def chat_ask():
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Request body must be a JSON object."}), 400

        question = str(payload.get("question") or "").strip()
        if not question:
            return jsonify({"success": False, "error": "Question cannot be empty."}), 400

        vendor = str(payload.get("vendor") or "").strip() or "firewall"
        filename = str(payload.get("filename") or "").strip() or "config"
        preview = payload.get("preview") if isinstance(payload.get("preview"), dict) else None
        source_text = payload.get("source_text") if isinstance(payload.get("source_text"), str) else None

        allow_env = live_device_access_allowed(app)
        sess, created = chat_store.get_or_create(request.cookies.get(_SESSION_COOKIE))

        digest_input = f"{vendor}|{filename}|{preview.get('source_digest') if preview else ''}|{len(source_text or '')}"
        digest = sha256(digest_input.encode("utf-8")).hexdigest()
        if sess.config_summary is None or sess.config_digest != digest or preview is not None:
            if preview is not None or source_text:
                sess.config_summary = build_config_summary(
                    vendor=vendor,
                    filename=filename,
                    preview=preview,
                    source_text=source_text,
                )
                sess.config_digest = digest
                sess.vendor = vendor
                sess.filename = filename
                detected = detect_vendor_from_content(source_text or "")
                sess.vendor_mismatch = detected if detected and detected != vendor else None

        if not sess.config_summary:
            return jsonify({"success": False, "error": "No active firewall configuration context provided."}), 404

        ok, reply = ask_gemini(
            question=question,
            config_summary=sess.config_summary,
            vendor=sess.vendor or vendor,
            filename=sess.filename or filename,
            chat_history=sess.chat_history,
            vendor_mismatch=sess.vendor_mismatch,
            api_key_override=sess.gemini_api_key,
            allow_env_fallback=allow_env,
        )
        if ok:
            sess.chat_history.append({"role": "user", "content": question})
            sess.chat_history.append({"role": "assistant", "content": reply})

        response = make_response(jsonify({
            "ok": ok,
            "reply": reply,
            "history": sess.chat_history,
            "vendor_mismatch": _mismatch_message(sess),
            "key_status": get_api_key_status(sess.gemini_api_key, allow_env_fallback=allow_env),
        }))
        _attach_cookie(response, sess.session_id, created)
        return response

    @app.route("/api/chat", methods=["DELETE"])
    def chat_clear():
        sess = chat_store.get(request.cookies.get(_SESSION_COOKIE))
        if sess is not None:
            sess.chat_history = []
        return jsonify({"ok": True})
