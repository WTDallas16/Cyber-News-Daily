#!/usr/bin/env python3
"""
Daily Cyber Threat Brief

Fetches recent cybersecurity news from public RSS feeds, ranks the most
relevant malware and cyber operations stories from the last 24 hours, and
delivers a concise plain text + HTML briefing via SMTP.

Setup:
1. Create a virtual environment with Python 3.11+.
2. Install dependencies from requirements.txt.
3. Copy .env.example to .env and fill in the required values.
4. Run locally with:
   python daily_cyber_brief.py

Cron example (7:00 AM local time):
0 7 * * * cd /path/to/Cyber_News_Codex && /usr/bin/env python3 daily_cyber_brief.py >> /tmp/daily_cyber_brief.log 2>&1

To add or remove news sources later, edit DEFAULT_FEEDS below or override them
with the CYBER_FEED_URLS environment variable.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import re
import smtplib
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import feedparser
import requests
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_TIMEOUT = 15
DEFAULT_MAX_STORIES = 10
STATE_RETENTION_DAYS = 14
DEFAULT_STATE_FILENAME = "daily_cyber_brief_state.json"
USER_AGENT = "DailyCyberThreatBrief/1.0 (+https://localhost)"

DEFAULT_FEEDS: list[dict[str, str]] = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "The Record", "url": "https://therecord.media/feed"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "CISA News", "url": "https://www.cisa.gov/news.xml"},
]

MALWARE_KEYWORDS: dict[str, int] = {
    "ransomware": 12,
    "malware": 11,
    "infostealer": 11,
    "stealer": 10,
    "trojan": 10,
    "botnet": 10,
    "loader": 10,
    "backdoor": 10,
    "wiper": 11,
    "worm": 10,
    "spyware": 9,
    "phishing": 9,
    "smishing": 8,
    "vishing": 8,
    "c2": 9,
    "command and control": 9,
}

CYBER_KEYWORDS: dict[str, int] = {
    **MALWARE_KEYWORDS,
    "exploit": 10,
    "zero-day": 12,
    "0-day": 12,
    "cve-": 9,
    "vulnerability": 7,
    "patch": 5,
    "breach": 8,
    "data breach": 9,
    "threat actor": 9,
    "apt": 7,
    "credential": 7,
    "compromise": 6,
    "incident response": 6,
    "lateral movement": 7,
    "supply chain": 9,
    "initial access": 8,
    "remote code execution": 10,
    "rce": 9,
    "ddos": 5,
    "cyberattack": 8,
    "cyber attack": 8,
    "extortion": 8,
}

LOW_SIGNAL_KEYWORDS: dict[str, int] = {
    "product review": -8,
    "conference": -5,
    "webinar": -6,
    "podcast": -4,
    "funding": -4,
    "opinion": -3,
    "career": -5,
    "privacy policy": -8,
}


@dataclass(slots=True)
class Article:
    title: str
    link: str
    source: str
    published: datetime
    summary: str = ""
    score: float = 0.0
    why_it_matters: str = ""
    category: str = "other"
    article_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Config:
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    email_from: str
    email_to: list[str]
    dry_run: bool
    max_stories: int
    min_score: float
    slack_webhook_url: str | None
    state_file: Path
    log_level: str
    smtp_use_ssl: bool
    smtp_starttls: bool
    feed_urls: list[dict[str, str]]


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        force=True,
    )


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer") from exc


def parse_email_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def default_state_file() -> Path:
    return Path(__file__).resolve().with_name(DEFAULT_STATE_FILENAME)


def resolve_state_file(raw_value: str) -> Path:
    value = (raw_value or "").strip()
    if not value:
        return default_state_file()

    path = Path(value).expanduser()
    if path.exists() and path.is_dir():
        return path / DEFAULT_STATE_FILENAME
    return path


def effective_log_level(config: Config) -> str:
    level = config.log_level.upper()
    if not config.dry_run and level == "INFO":
        return "WARNING"
    return level


def load_config() -> Config:
    load_dotenv()

    dry_run = env_bool("DRY_RUN", False)
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = env_int("SMTP_PORT", 587)
    smtp_username = os.getenv("SMTP_USERNAME", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    email_from = os.getenv("EMAIL_FROM", "").strip()
    email_to = parse_email_list(os.getenv("EMAIL_TO", ""))

    missing = []
    if not dry_run:
        if not smtp_host:
            missing.append("SMTP_HOST")
        if not smtp_username:
            missing.append("SMTP_USERNAME")
        if not smtp_password:
            missing.append("SMTP_PASSWORD")
    if not email_from:
        missing.append("EMAIL_FROM")
    if not email_to:
        missing.append("EMAIL_TO")

    if missing:
        raise ValueError(
            "Missing required environment variables: " + ", ".join(sorted(set(missing)))
        )

    state_file = resolve_state_file(os.getenv("STATE_FILE", ""))

    feed_override = os.getenv("CYBER_FEED_URLS", "").strip()
    if feed_override:
        feed_urls = [
            {"name": infer_feed_name(url.strip()), "url": url.strip()}
            for url in feed_override.split(",")
            if url.strip()
        ]
    else:
        feed_urls = DEFAULT_FEEDS

    return Config(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        email_from=email_from,
        email_to=email_to,
        dry_run=dry_run,
        max_stories=max(1, min(env_int("MAX_STORIES", DEFAULT_MAX_STORIES), 10)),
        min_score=float(os.getenv("MIN_RELEVANCE_SCORE", "8")),
        slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL", "").strip() or None,
        state_file=state_file,
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        smtp_use_ssl=env_bool("SMTP_USE_SSL", False),
        smtp_starttls=env_bool("SMTP_STARTTLS", True),
        feed_urls=feed_urls,
    )


def infer_feed_name(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.replace("www.", "").split(":")[0]
    return host or "Custom Feed"


def build_session() -> requests.Session:
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def canonicalize_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    filtered_query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if not key.lower().startswith(("utm_", "mc_", "fbclid", "gclid"))
    ]
    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/"),
            "",
            urlencode(filtered_query),
            "",
        )
    )


def normalize_text(value: str) -> str:
    value = BeautifulSoup(value or "", "html.parser").get_text(" ", strip=True)
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if hasattr(value, "tm_year"):
        return datetime(*value[:6], tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = date_parser.parse(value)
            return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError, OverflowError):
            return None
    return None


def fetch_feeds(session: requests.Session, feeds: list[dict[str, str]]) -> list[Article]:
    articles: list[Article] = []
    for feed in feeds:
        name = feed["name"]
        url = feed["url"]
        try:
            logging.info("Fetching feed: %s", url)
            response = session.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            parsed = feedparser.parse(response.content)
            if parsed.bozo:
                logging.warning("Feed parser reported an issue for %s", url)
            for entry in parsed.entries:
                article = build_article_from_entry(entry, name)
                if article:
                    articles.append(article)
        except Exception:
            logging.exception("Failed to fetch or parse feed %s", url)
    return articles


def build_article_from_entry(entry: Any, feed_name: str) -> Article | None:
    title = normalize_text(getattr(entry, "title", ""))
    link = canonicalize_url(getattr(entry, "link", ""))
    published = (
        parse_datetime(getattr(entry, "published_parsed", None))
        or parse_datetime(getattr(entry, "updated_parsed", None))
        or parse_datetime(getattr(entry, "published", None))
        or parse_datetime(getattr(entry, "updated", None))
    )

    if not title or not link or not published:
        return None

    source = normalize_text(
        getattr(getattr(entry, "source", None), "title", "") or feed_name
    )
    summary_candidates = [
        getattr(entry, "summary", ""),
        getattr(entry, "description", ""),
        getattr(entry, "subtitle", ""),
    ]
    metadata: dict[str, Any] = {}
    tags = getattr(entry, "tags", None) or []
    if tags:
        metadata["tags"] = [normalize_text(getattr(tag, "term", "")) for tag in tags]
    summary = next((normalize_text(item) for item in summary_candidates if item), "")

    article_id = fingerprint_story(title, link)
    return Article(
        title=title,
        link=link,
        source=source,
        published=published,
        summary=summary,
        article_id=article_id,
        metadata=metadata,
    )


def fingerprint_story(title: str, link: str) -> str:
    normalized_title = re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()
    payload = f"{normalized_title}|{canonicalize_url(link)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def filter_by_recency(articles: list[Article], now_utc: datetime) -> list[Article]:
    cutoff = now_utc - timedelta(hours=24)
    recent_articles = [article for article in articles if article.published >= cutoff]
    logging.info(
        "Retained %d of %d stories from the last 24 hours",
        len(recent_articles),
        len(articles),
    )
    return recent_articles


def title_similarity(left: str, right: str) -> float:
    left_tokens = set(re.findall(r"[a-z0-9]{3,}", left.lower()))
    right_tokens = set(re.findall(r"[a-z0-9]{3,}", right.lower()))
    if not left_tokens or not right_tokens:
        return 0.0
    intersection = len(left_tokens & right_tokens)
    union = len(left_tokens | right_tokens)
    return intersection / union if union else 0.0


def deduplicate_articles(articles: list[Article]) -> list[Article]:
    unique: list[Article] = []
    seen_ids: set[str] = set()

    for article in sorted(articles, key=lambda item: item.published, reverse=True):
        canonical_id = fingerprint_story(article.title, article.link)
        if canonical_id in seen_ids:
            continue

        duplicate = False
        for existing in unique:
            same_link = canonicalize_url(existing.link) == canonicalize_url(article.link)
            same_title = title_similarity(existing.title, article.title) >= 0.82
            if same_link or same_title:
                duplicate = True
                break

        if duplicate:
            continue

        seen_ids.add(canonical_id)
        unique.append(article)

    logging.info("Deduplicated %d stories down to %d", len(articles), len(unique))
    return unique


def keyword_score(text: str, keywords: dict[str, int]) -> float:
    lowered = text.lower()
    score = 0.0
    for keyword, weight in keywords.items():
        count = lowered.count(keyword)
        if count:
            score += weight * min(count, 3)
    return score


def classify_category(article: Article) -> str:
    combined = " ".join(
        [
            article.title,
            article.summary,
            " ".join(article.metadata.get("tags", [])),
        ]
    ).lower()
    return "malware" if keyword_score(combined, MALWARE_KEYWORDS) >= 10 else "other"


def score_article(article: Article, now_utc: datetime) -> float:
    combined = " ".join(
        [
            article.title,
            article.summary,
            " ".join(article.metadata.get("tags", [])),
        ]
    )
    base_score = keyword_score(article.title, CYBER_KEYWORDS) * 1.8
    base_score += keyword_score(combined, CYBER_KEYWORDS)
    base_score += keyword_score(combined, LOW_SIGNAL_KEYWORDS)

    age_hours = max((now_utc - article.published).total_seconds() / 3600, 0)
    recency_bonus = max(0.0, 6.0 - (age_hours / 4.0))
    source_bonus = 1.5 if article.source.lower() in {"bleepingcomputer", "the record", "securityweek"} else 0.0

    article.category = classify_category(article)
    if article.category == "malware":
        base_score += 5

    score = base_score + recency_bonus + source_bonus
    logging.debug("Scored article %.2f: %s", score, article.title)
    return score


def select_top_stories(
    articles: list[Article],
    config: Config,
    now_utc: datetime,
    state: dict[str, Any],
) -> list[Article]:
    already_sent = set(state.get("sent_articles", {}).keys())
    candidates: list[Article] = []
    for article in articles:
        if article.article_id in already_sent:
            logging.info("Skipping previously sent story: %s", article.title)
            continue
        article.score = score_article(article, now_utc)
        if article.score >= config.min_score:
            candidates.append(article)

    candidates.sort(key=lambda item: (item.score, item.published), reverse=True)
    selected = candidates[: config.max_stories]
    logging.info("Selected %d stories above score threshold %.2f", len(selected), config.min_score)
    return selected


def extract_preview_from_article(session: requests.Session, url: str) -> str:
    try:
        response = session.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        meta_candidates = [
            soup.find("meta", attrs={"property": "og:description"}),
            soup.find("meta", attrs={"name": "description"}),
            soup.find("meta", attrs={"name": "twitter:description"}),
        ]
        for meta in meta_candidates:
            if meta and meta.get("content"):
                preview = normalize_text(meta["content"])
                if len(preview) >= 80:
                    return preview

        paragraphs = [
            normalize_text(node.get_text(" ", strip=True))
            for node in soup.find_all("p", limit=6)
        ]
        merged = " ".join(text for text in paragraphs if len(text) >= 40)
        return merged[:1200]
    except Exception:
        logging.exception("Failed to extract article preview from %s", url)
        return ""


def split_sentences(text: str) -> list[str]:
    cleaned = normalize_text(text)
    if not cleaned:
        return []
    parts = re.split(r"(?<=[.!?])\s+", cleaned)
    return [part.strip() for part in parts if len(part.strip()) > 25]


def summarize_content(article: Article, session: requests.Session) -> tuple[str, str]:
    raw_text = article.summary
    if len(raw_text) < 180:
        fetched_preview = extract_preview_from_article(session, article.link)
        if fetched_preview:
            raw_text = f"{raw_text} {fetched_preview}".strip()

    sentences = split_sentences(raw_text)
    if not sentences:
        summary = (
            "Limited article details were available from the feed. Review the linked story for full context and technical specifics."
        )
    else:
        prioritized = sorted(
            sentences,
            key=lambda sentence: keyword_score(sentence, CYBER_KEYWORDS),
            reverse=True,
        )
        chosen: list[str] = []
        for sentence in prioritized:
            if sentence not in chosen:
                chosen.append(sentence)
            if len(chosen) >= 3:
                break
        if len(chosen) < 2:
            for sentence in sentences:
                if sentence not in chosen:
                    chosen.append(sentence)
                if len(chosen) >= 2:
                    break
        summary = " ".join(chosen[:4])

    why = generate_why_it_matters(article, summary)
    return summary, why


def generate_why_it_matters(article: Article, summary: str) -> str:
    text = f"{article.title} {summary}".lower()
    if any(keyword in text for keyword in ("zero-day", "0-day", "cve-", "remote code execution", "exploit")):
        return "Why it matters: This may require rapid patch validation, exposure assessment, and detection tuning for active exploitation."
    if any(keyword in text for keyword in ("ransomware", "extortion", "wiper")):
        return "Why it matters: This is directly relevant to disruption and recovery planning, especially for backup integrity, containment, and ransomware response readiness."
    if any(keyword in text for keyword in ("phishing", "credential", "infostealer", "stealer")):
        return "Why it matters: This can affect user-focused defenses and credential protection, with implications for email filtering, MFA, and identity monitoring."
    if any(keyword in text for keyword in ("breach", "compromise", "threat actor", "apt")):
        return "Why it matters: This may indicate new attacker activity or tactics worth mapping into detections, threat hunting, and executive awareness."
    return "Why it matters: This is operationally relevant for vulnerability management, detection coverage, and incident readiness."


def enrich_stories(articles: list[Article], session: requests.Session) -> None:
    for article in articles:
        summary, why = summarize_content(article, session)
        article.summary = summary
        article.why_it_matters = why


def format_timestamp(dt: datetime) -> str:
    return dt.astimezone().strftime("%Y-%m-%d %I:%M %p %Z")


def compose_no_story_message(subject: str, now_utc: datetime) -> tuple[str, str]:
    text_body = (
        f"{subject}\n\n"
        "No major malware or cybersecurity stories met the briefing criteria in the last 24 hours.\n"
        f"Window checked: {(now_utc - timedelta(hours=24)).astimezone().strftime('%Y-%m-%d %I:%M %p %Z')} "
        f"to {now_utc.astimezone().strftime('%Y-%m-%d %I:%M %p %Z')}.\n"
    )
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #1f2937;">
        <h2>{html.escape(subject)}</h2>
        <p>No major malware or cybersecurity stories met the briefing criteria in the last 24 hours.</p>
        <p><strong>Window checked:</strong> {html.escape((now_utc - timedelta(hours=24)).astimezone().strftime('%Y-%m-%d %I:%M %p %Z'))}
        to {html.escape(now_utc.astimezone().strftime('%Y-%m-%d %I:%M %p %Z'))}</p>
      </body>
    </html>
    """.strip()
    return text_body, html_body


def render_story_text(article: Article) -> str:
    return (
        f"{article.title}\n"
        f"Source: {article.source}\n"
        f"Published: {format_timestamp(article.published)}\n"
        f"Summary: {article.summary}\n"
        f"{article.why_it_matters}\n"
        f"Link: {article.link}\n"
    )


def render_story_html(article: Article) -> str:
    return f"""
    <div style="margin-bottom: 24px; padding-bottom: 18px; border-bottom: 1px solid #d1d5db;">
      <h3 style="margin: 0 0 8px 0; font-size: 18px;">
        <a href="{html.escape(article.link)}" style="color: #0f172a; text-decoration: none;">{html.escape(article.title)}</a>
      </h3>
      <p style="margin: 0 0 8px 0; color: #475569;">
        <strong>Source:</strong> {html.escape(article.source)}<br>
        <strong>Published:</strong> {html.escape(format_timestamp(article.published))}
      </p>
      <p style="margin: 0 0 8px 0;">{html.escape(article.summary)}</p>
      <p style="margin: 0 0 8px 0;"><strong>{html.escape(article.why_it_matters)}</strong></p>
      <p style="margin: 0;"><a href="{html.escape(article.link)}">Read more</a></p>
    </div>
    """.strip()


def format_email(subject: str, articles: list[Article], now_utc: datetime) -> tuple[str, str]:
    if not articles:
        return compose_no_story_message(subject, now_utc)

    malware_articles = [article for article in articles if article.category == "malware"]
    other_articles = [article for article in articles if article.category != "malware"]

    intro = (
        f"Daily Cyber Threat Brief for {now_utc.astimezone().strftime('%Y-%m-%d')}. "
        f"This briefing highlights {len(articles)} notable cybersecurity stories published in the last 24 hours, "
        "ranked for malware and security operations relevance."
    )

    text_parts = [subject, "", intro, ""]
    text_parts.extend(["Malware / Ransomware Highlights", "-" * 33, ""])
    if malware_articles:
        for article in malware_articles:
            text_parts.append(render_story_text(article))
    else:
        text_parts.append("No dedicated malware or ransomware stories were selected today.\n")

    text_parts.extend(["Other Notable Cybersecurity News", "-" * 32, ""])
    if other_articles:
        for article in other_articles:
            text_parts.append(render_story_text(article))
    else:
        text_parts.append("No additional notable cybersecurity stories were selected today.\n")

    text_body = "\n".join(text_parts).strip() + "\n"

    html_sections: list[str] = [
        "<html>",
        '<body style="font-family: Arial, sans-serif; color: #1f2937; line-height: 1.5;">',
        f'<h2 style="margin-bottom: 8px;">{html.escape(subject)}</h2>',
        f"<p>{html.escape(intro)}</p>",
    ]

    html_sections.append('<h3 style="margin-top: 28px; color: #991b1b;">Malware / Ransomware Highlights</h3>')
    if malware_articles:
        html_sections.extend(render_story_html(article) for article in malware_articles)
    else:
        html_sections.append("<p>No dedicated malware or ransomware stories were selected today.</p>")

    html_sections.append('<h3 style="margin-top: 28px; color: #0f172a;">Other Notable Cybersecurity News</h3>')
    if other_articles:
        html_sections.extend(render_story_html(article) for article in other_articles)
    else:
        html_sections.append("<p>No additional notable cybersecurity stories were selected today.</p>")

    html_sections.extend(["</body>", "</html>"])
    html_body = "\n".join(html_sections)
    return text_body, html_body


def send_email(config: Config, subject: str, text_body: str, html_body: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.email_from
    message["To"] = ", ".join(config.email_to)
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    if config.smtp_use_ssl:
        with smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=DEFAULT_TIMEOUT) as smtp:
            smtp.login(config.smtp_username, config.smtp_password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=DEFAULT_TIMEOUT) as smtp:
            smtp.ehlo()
            if config.smtp_starttls:
                smtp.starttls()
                smtp.ehlo()
            smtp.login(config.smtp_username, config.smtp_password)
            smtp.send_message(message)


def post_to_slack(webhook_url: str, subject: str, articles: list[Article], dry_run: bool) -> None:
    lines = [f"*{subject}*"]
    if not articles:
        lines.append("No major malware or cybersecurity stories met the briefing criteria in the last 24 hours.")
    else:
        for article in articles[:5]:
            lines.append(f"- <{article.link}|{article.title}> ({article.source})")

    payload = {"text": "\n".join(lines)}
    if dry_run:
        logging.info("DRY_RUN enabled; Slack payload:\n%s", payload["text"])
        return

    response = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
    response.raise_for_status()


def load_state(state_file: Path) -> dict[str, Any]:
    if state_file.exists() and state_file.is_dir():
        fallback = state_file / DEFAULT_STATE_FILENAME
        logging.error(
            "STATE_FILE points to a directory (%s). Using %s instead.",
            state_file,
            fallback,
        )
        state_file = fallback

    if not state_file.exists():
        return {"sent_articles": {}}
    try:
        with state_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            if "sent_articles" not in data or not isinstance(data["sent_articles"], dict):
                return {"sent_articles": {}}
            return data
    except Exception:
        logging.exception("Failed to load state file %s", state_file)
        return {"sent_articles": {}}


def save_state(state_file: Path, state: dict[str, Any]) -> None:
    if state_file.exists() and state_file.is_dir():
        fallback = state_file / DEFAULT_STATE_FILENAME
        logging.error(
            "STATE_FILE points to a directory (%s). Writing to %s instead.",
            state_file,
            fallback,
        )
        state_file = fallback

    state_file.parent.mkdir(parents=True, exist_ok=True)
    with state_file.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)


def prune_state(state: dict[str, Any], now_utc: datetime) -> dict[str, Any]:
    sent_articles = state.get("sent_articles", {})
    cutoff = now_utc - timedelta(days=STATE_RETENTION_DAYS)
    pruned = {}
    for article_id, sent_at in sent_articles.items():
        parsed = parse_datetime(sent_at)
        if parsed and parsed >= cutoff:
            pruned[article_id] = parsed.isoformat()
    state["sent_articles"] = pruned
    return state


def update_state_with_sent_articles(state: dict[str, Any], articles: list[Article], now_utc: datetime) -> dict[str, Any]:
    sent_articles = state.setdefault("sent_articles", {})
    for article in articles:
        sent_articles[article.article_id] = now_utc.isoformat()
    return state


def print_dry_run_output(subject: str, text_body: str, html_body: str) -> None:
    divider = "=" * 80
    print(divider)
    print(f"Subject: {subject}")
    print(divider)
    print("PLAIN TEXT VERSION")
    print(divider)
    print(text_body)
    print(divider)
    print("HTML VERSION")
    print(divider)
    print(html_body)


def main() -> int:
    setup_logging(os.getenv("LOG_LEVEL", "INFO"))
    try:
        config = load_config()
        setup_logging(effective_log_level(config))
        now_utc = datetime.now(timezone.utc)
        subject = f"Daily Cyber Threat Brief - {now_utc.astimezone().strftime('%Y-%m-%d')}"

        state = prune_state(load_state(config.state_file), now_utc)
        session = build_session()

        fetched_articles = fetch_feeds(session, config.feed_urls)
        recent_articles = filter_by_recency(fetched_articles, now_utc)
        deduped_articles = deduplicate_articles(recent_articles)
        selected_articles = select_top_stories(deduped_articles, config, now_utc, state)
        enrich_stories(selected_articles, session)

        text_body, html_body = format_email(subject, selected_articles, now_utc)

        if config.dry_run:
            print_dry_run_output(subject, text_body, html_body)
        else:
            send_email(config, subject, text_body, html_body)
            logging.info("Email sent to %s", ", ".join(config.email_to))
            print("News Sent")

        if config.slack_webhook_url:
            try:
                post_to_slack(config.slack_webhook_url, subject, selected_articles, config.dry_run)
            except Exception:
                logging.exception("Failed to send Slack notification")

        if selected_articles:
            state = update_state_with_sent_articles(state, selected_articles, now_utc)
            save_state(config.state_file, state)
            logging.info("Updated state file: %s", config.state_file)
        elif config.dry_run:
            logging.info("No stories selected; state file not updated during dry run")
        else:
            save_state(config.state_file, state)

        return 0
    except Exception:
        logging.exception("Daily cyber brief failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
