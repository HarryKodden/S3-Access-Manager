import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError


class AWSAdmin:
    def __init__(self, access_key: Optional[str] = None, secret_key: Optional[str] = None, region: Optional[str] = None, endpoint: Optional[str] = None):
        session_kwargs = {}
        client_kwargs = {}
        if access_key and secret_key:
            session_kwargs["aws_access_key_id"] = access_key
            session_kwargs["aws_secret_access_key"] = secret_key
        if region:
            session_kwargs["region_name"] = region
            client_kwargs["region_name"] = region
        if endpoint:
            client_kwargs["endpoint_url"] = endpoint

        self.session = boto3.Session(**session_kwargs) if session_kwargs else boto3.Session()
        self.iam = self.session.client("iam", **client_kwargs)

    def create_user(self, email: str) -> None:
        try:
            self.iam.create_user(UserName=email)
        except ClientError as e:
            # Ignore if user already exists
            if e.response.get("Error", {}).get("Code") in ("EntityAlreadyExists", "EntityAlreadyExistsException"):
                return
            raise

    def get_access_key_count(self, username: str) -> int:
        try:
            resp = self.iam.list_access_keys(UserName=username)
            return len(resp.get("AccessKeyMetadata", []))
        except ClientError:
            return 0

    def create_credential(self, email: str, credential_name: str, policy_doc: Dict[str, Any]) -> Dict[str, Any]:
        # ensure user
        try:
            self.create_user(email)
        except Exception as e:
            raise

        # enforce max 2 keys
        if self.get_access_key_count(email) >= 2:
            raise RuntimeError("user already has maximum access keys (2)")

        try:
            res = self.iam.create_access_key(UserName=email)
            ak = res["AccessKey"]["AccessKeyId"]
            sk = res["AccessKey"]["SecretAccessKey"]
        except ClientError as e:
            raise

        # attach inline policy
        policy_name = f"{email}-{credential_name}-policy".replace("@", "-")
        try:
            self.iam.put_user_policy(UserName=email, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        except ClientError:
            # best-effort: try to delete created key if policy attach fails
            try:
                self.iam.delete_access_key(UserName=email, AccessKeyId=ak)
            except Exception:
                pass
            raise

        return {"access_key": ak, "secret_key": sk, "backend_data": {"policy_name": policy_name, "type": "iam-user", "user": email}}

    def delete_credential(self, email: str, credential_name: str, backend_data: Optional[Dict[str, Any]] = None) -> None:
        # delete inline policy if present
        if backend_data:
            policy_name = backend_data.get("policy_name")
            if policy_name:
                try:
                    self.iam.delete_user_policy(UserName=email, PolicyName=policy_name)
                except ClientError:
                    pass

        # delete all access keys for user
        try:
            resp = self.iam.list_access_keys(UserName=email)
            for k in resp.get("AccessKeyMetadata", []):
                try:
                    self.iam.delete_access_key(UserName=email, AccessKeyId=k.get("AccessKeyId"))
                except ClientError:
                    pass
        except ClientError:
            pass

    def create_user_profile(self, email: str, credential_name: str, access_key: str, secret_key: str, session_token: str, region: str, endpoint: str) -> None:
        # Write profile to ~/.aws/config and ~/.aws/credentials (best-effort)
        try:
            home = str(Path.home())
        except Exception:
            home = os.path.expanduser("~")

        aws_dir = Path(home) / ".aws"
        aws_dir.mkdir(parents=True, exist_ok=True)

        email_prefix = email.split("@")[0]
        sanitized = credential_name.lower().replace(" ", "-").replace("_", "-")
        profile = f"{email_prefix}-{sanitized}"

        config_path = aws_dir / "config"
        cred_path = aws_dir / "credentials"

        config_text = ""
        if config_path.exists():
            config_text = config_path.read_text()
            # remove existing profile section if present
            if f"[profile {profile}]" in config_text or f"[{profile}]" in config_text:
                # naive removal: skip - keep simple
                pass

        config_text += f"\n[profile {profile}]\nregion = {region or ''}\nendpoint_url = {endpoint or ''}\nsignature_version = s3v4\npayload_signing_enabled = true\naddressing_style = path\n"
        config_path.write_text(config_text)

        cred_text = ""
        if cred_path.exists():
            cred_text = cred_path.read_text()
            if f"[{profile}]" in cred_text:
                pass

        if session_token:
            cred_text += f"\n[{profile}]\naws_access_key_id = {access_key}\naws_secret_access_key = {secret_key}\naws_session_token = {session_token}\n"
        else:
            cred_text += f"\n[{profile}]\naws_access_key_id = {access_key}\naws_secret_access_key = {secret_key}\n"

        cred_path.write_text(cred_text)

    def remove_user_profile(self, email: str, credential_name: str) -> None:
        try:
            home = str(Path.home())
        except Exception:
            home = os.path.expanduser("~")
        aws_dir = Path(home) / ".aws"
        email_prefix = email.split("@")[0]
        sanitized = credential_name.lower().replace(" ", "-").replace("_", "-")
        profile = f"{email_prefix}-{sanitized}"

        for p in [aws_dir / "config", aws_dir / "credentials"]:
            if not p.exists():
                continue
            try:
                content = p.read_text()
            except Exception:
                continue
            lines = content.splitlines()
            new_lines = []
            in_profile = False
            for line in lines:
                if line.strip().startswith(f"[profile {profile}]") or line.strip().startswith(f"[{profile}]"):
                    in_profile = True
                    continue
                if in_profile:
                    if line.strip().startswith("["):
                        in_profile = False
                        new_lines.append(line)
                    else:
                        continue
                else:
                    new_lines.append(line)
            try:
                p.write_text("\n".join(new_lines).rstrip() + "\n")
            except Exception:
                pass
