from setuptools import setup, find_packages

# 读取 README.md 作为长描述
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="jsscan",
    version="1.0.0",
    author="Your Name",
    author_email="your@email.com",
    description="Scan JavaScript files for sensitive information leaks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/jsscan",
    packages=find_packages(),
    py_modules=["jsscan"],  # 脚本文件名为 jsscan.py
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "jsscan=jsscan:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)