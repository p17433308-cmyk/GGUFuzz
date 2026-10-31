from setuptools import setup, find_packages

setup(
    name="ggufuzz",
    version="1.0.0",
    description="AI Model File Weaponization Framework",
    author="Security Research Team",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "ggufuzz=ggufuzz.cli:main",
        ],
    },
)
