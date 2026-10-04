"""kiwiagent: memory_notifications=new_skills.

SmartBuddy users should hear when their buddy learns a NEW skill, in plain
language, but not about memory updates or patches to existing skills
("💾 Self-improvement review: Patched SKILL.md in skill '…'").
"""
import json

from agent.background_review import (
    format_background_review_notice,
    summarize_background_review_actions,
)

SKILL_MD = (
    "---\n"
    "name: recurring-service-monitor\n"
    "description: Check a website on a schedule and tell you when it changes.\n"
    "---\n\n# Recurring service monitor\n..."
)


def _call(tcid, name, args):
    return {"role": "assistant", "tool_calls": [
        {"id": tcid, "function": {"name": name, "arguments": json.dumps(args)}}]}


def _result(tcid, payload):
    return {"role": "tool", "tool_call_id": tcid, "content": json.dumps(payload)}


def _review(*pairs):
    messages = []
    for tcid, name, args, payload in pairs:
        messages += [_call(tcid, name, args), _result(tcid, payload)]
    return messages


CREATE = ("c1", "skill_manage",
          {"action": "create", "name": "recurring-service-monitor", "content": SKILL_MD},
          {"success": True, "message": "Skill 'recurring-service-monitor' created."})
PATCH = ("c2", "skill_manage",
         {"action": "patch", "name": "personal-schedule-management", "old_string": "a", "new_string": "b"},
         {"success": True, "message": "Patched SKILL.md in skill 'personal-schedule-management' (1 replacement)."})
MEMORY = ("c3", "memory",
          {"action": "add", "target": "user", "content": "Daughter Victoria does ballet"},
          {"success": True, "message": "Entry added", "target": "user"})


def test_new_skills_mode_KeepsOnlyCreatedSkills():
    actions = summarize_background_review_actions(
        _review(CREATE, PATCH, MEMORY), [], notification_mode="new_skills")

    assert len(actions) == 1
    assert "recurring-service-monitor" in actions[0]
    assert "Check a website on a schedule" in actions[0]


def test_new_skills_mode_PatchesAndMemoryOnly_ReturnsNothing():
    actions = summarize_background_review_actions(
        _review(PATCH, MEMORY), [], notification_mode="new_skills")

    assert actions == []


def test_new_skills_mode_FailedCreate_ReturnsNothing():
    failed = (CREATE[0], CREATE[1], CREATE[2], {"success": False, "error": "exists"})

    assert summarize_background_review_actions(
        _review(failed), [], notification_mode="new_skills") == []


def test_new_skills_mode_ChineseDescription_ChineseWording():
    zh = ("c9", "skill_manage",
          {"action": "create", "name": "kids-activities",
           "content": "---\nname: kids-activities\ndescription: 管理孩子的课外班时间表\n---\n"},
          {"success": True, "message": "Skill 'kids-activities' created."})

    actions = summarize_background_review_actions(_review(zh), [], notification_mode="new_skills")

    assert actions and "我学会了一个新技能" in actions[0]
    assert "管理孩子的课外班时间表" in actions[0]


def test_new_skills_mode_NoDescription_StillNamesSkill():
    bare = ("c8", "skill_manage", {"action": "create", "name": "tidy-notes", "content": "# no frontmatter"},
            {"success": True, "message": "Skill 'tidy-notes' created."})

    actions = summarize_background_review_actions(_review(bare), [], notification_mode="new_skills")

    assert actions and "tidy-notes" in actions[0]


def test_format_notice_NewSkillsMode_NoOperatorPrefix():
    notice = format_background_review_notice(["🧠 I learned a new skill: x"], "new_skills")

    assert notice == "🧠 I learned a new skill: x"
    assert "Self-improvement review" not in notice


def test_format_notice_DefaultMode_KeepsUpstreamFormat():
    notice = format_background_review_notice(["Memory updated", "Skill created."], "on")

    assert notice == "💾 Self-improvement review: Memory updated · Skill created."


def test_on_mode_Unchanged_StillReportsPatches():
    actions = summarize_background_review_actions(_review(PATCH), [], notification_mode="on")

    assert any("Patched SKILL.md" in a for a in actions)
