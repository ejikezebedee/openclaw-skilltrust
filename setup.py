from setuptools import find_packages, setup


setup(
    name="openclaw-skilltrust",
    version="0.1.0",
    description="Open-source trust and audit layer for AI-agent skills, MCP tools, plugins, and connectors.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    license="MIT",
    author="OpenClaw SkillTrust contributors",
    author_email="contributors@example.invalid",
    packages=find_packages(),
    python_requires=">=3.10",
    extras_require={"test": ["pytest>=8"]},
    entry_points={"console_scripts": ["skilltrust=skilltrust.cli:main"]},
)
