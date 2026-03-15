# Project Argus

> **WARNING: FOR LOCAL USE ONLY. Run this tool exclusively against the bundled `/target` application. Never point it at systems you do not own or have explicit written permission to test. Unauthorized use is illegal.**

Project Argus is an autonomous, multi-agent AI pentesting tool. It uses a [CrewAI](https://github.com/joaomdmoura/crewAI) agent swarm — Recon, SQLi Hunter, XSS Specialist, and Auth Auditor — orchestrated through a FastAPI backend. The frontend, built with Next.js and Tailwind CSS, lets you configure and launch scans and renders structured vulnerability reports in real time.

The included `/target` app is an intentionally vulnerable Flask application. It is the only sanctioned scan target.
