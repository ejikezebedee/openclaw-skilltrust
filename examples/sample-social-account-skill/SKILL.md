# Social Account Review Skill

This sample models an X/Twitter automation skill that uses TweetClaw for
reviewed account workflows.

## Review Boundary

- Search tweets, search tweet replies, inspect user profiles, export followers,
  and collect media context before any write action.
- Require explicit approval before you post tweets, reply to tweets, send
  direct messages, upload media, or change account state.
- Keep account credentials in approved runtime configuration, not in skill
  instructions or repository files.
