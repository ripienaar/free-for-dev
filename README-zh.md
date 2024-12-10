# free-for.dev

开发者和开源作者现在拥有许多提供免费服务级别的服务，但找齐所有服务需要时间以做出知情的选择。

这是一个包含软件（SaaS、PaaS、IaaS 等）和其他提供商提供免费开发者服务级别的列表。

这份列表特定于基础设施开发者（系统管理员、DevOps 实践者等）可能会发现有用的工具。我们喜欢所有免费服务，但保持主题一致会更好。有时这条界限模糊，所以这是一个带有观点的列表；如果我不接受你的贡献，请不要感到冒犯。

这个列表来源于1600多人的拉取请求、评审、想法和工作。您也可以通过发送 [Pull Requests](https://github.com/ripienaar/free-for-dev) 来帮助添加更多服务或删除其服务内容已更改或被淘汰的服务。

[![Track Awesome List](https://www.trackawesomelist.com/badge.svg)](https://www.trackawesomelist.com/ripienaar/free-for-dev)

**注意**：此列表仅适用于即服务（as-a-Service）提供，并不适用于自托管软件。符合条件的服务必须提供免费级别，而不仅仅是免费试用。如果按时间划分，免费级别必须至少持续一年。我们还从安全角度考虑免费级别，因此单点登录（SSO）是可以的，但我不会接受那些将 TLS 限制为仅付费级别的服务。

# 目录

  * [主要云服务商的永久免费限制](#major-cloud-providers)
  * [云管理解决方案](#cloud-management-solutions)
  * [分析、事件和统计](#analytics-events-and-statistics)
  * [API、数据和机器学习](#apis-data-and-ml)
  * [工件存储库](#artifact-repos)
  * [BaaS](#baas)
  * [低代码平台](#low-code-platform)
  * [CDN 和保护](#cdn-and-protection)
  * [CI 和 CD](#ci-and-cd)
  * [CMS](#cms)
  * [代码生成](#code-generation)
  * [代码质量](#code-quality)
  * [代码搜索和浏览](#code-search-and-browsing)
  * [崩溃和异常处理](#crash-and-exception-handling)
  * [地图上的数据可视化](#data-visualization-on-maps)
  * [托管数据服务](#managed-data-services)
  * [设计和用户接口](#design-and-ui)
  * [设计灵感](#design-inspiration)
  * [开发博客网站](#dev-blogging-sites)
  * [DNS](#dns)
  * [Docker 相关](#docker-related)
  * [域名](#domain)
  * [教育和职业发展](#education-and-career-development)
  * [电子邮件](#email)
  * [特性切换管理平台](#feature-toggles-management-platforms)
  * [字体](#font)
  * [表格](#forms)
  * [生成式 AI](#generative-ai)
  * [IaaS](#iaas)
  * [IDE 和代码编辑](#ide-and-code-editing)
  * [国际手机号码验证 API 和 SDK](#international-mobile-number-verification-api-and-sdk)
  * [问题跟踪和项目管理](#issue-tracking-and-project-management)
  * [日志管理](#log-management)
  * [翻译管理](#translation-management)
  * [监控](#monitoring)
  * [PaaS](#paas)
  * [包构建系统](#package-build-system)
  * [安全性和 PKI](#security-and-pki)
  * [身份验证、授权和用户管理](#authentication-authorization-and-user-management)
  * [源代码存储库](#source-code-repos)
  * [存储和媒体处理](#storage-and-media-processing)
  * [隧道、WebRTC、Web Socket 服务器和其他路由器](#tunneling-webrtc-web-socket-servers-and-other-routers)
  * [测试](#testing)
  * [团队和协作工具](#tools-for-teams-and-collaboration)
  * [翻译管理](#translation-management)
  * [虚拟专用网络](#vagrant-related)
  * [访问者会话录制](#visitor-session-recording)
  * [网站托管](#web-hosting)
  * [评论平台](#commenting-platforms)
  * [基于浏览器的硬件仿真](#browser-based-hardware-emulation-written-in-javascript)
  * [远程桌面工具](#remote-desktop-tools)
  * [游戏开发](#game-development)
  * [其他免费资源](#other-free-resources)

## 主要云服务商

  * [Google Cloud Platform](https://cloud.google.com)
    * App Engine - 每天 28 小时前端实例时间，9 小时后端实例时间
    * Cloud Firestore - 1GB 存储，每天 50,000 次读取，20,000 次写入，20,000 次删除
    * Compute Engine - 1个非抢占的 e2-micro，30GB HDD，5GB 快照存储（限某些地区），每月从北美到所有地区的 1GB 网络出口（不包括中国和澳大利亚）
    * Cloud Storage - 5GB，1GB 网络出口
    * Cloud Shell - 基于 Web 的 Linux Shell/主要 IDE，带有 5GB 的持久性存储。每周限制 60 小时
    * Cloud Pub/Sub - 每月 10GB 消息
    * Cloud Functions - 每月 200 万次调用（包括背景和 HTTP 调用）
    * Cloud Run - 每月 200 万次请求，360,000 GB-秒内存，180,000 vCPU-秒计算时间， 每月从北美出口 1GB 网络
    * Google Kubernetes Engine - 对于 1 个区域集群没有集群管理费。每个用户节点按标准 Compute Engine 定价收费
    * BigQuery - 每月 1TB 查询，每月 10GB 存储
    * Cloud Build - 每天 120 构建分钟
    * Cloud Source Repositories - 最多 5 名用户，50 GB 存储，50 GB 出口
    * [Google Colab](https://colab.research.google.com/) - 免费 Jupyter Notebooks 开发环境。
    * 完整详细列表 - https://cloud.google.com/free

  * [Amazon Web Services](https://aws.amazon.com)
    * [CloudFront](https://aws.amazon.com/cloudfront/) - 每月 1TB 出口和每月 2M 次函数调用
    * [CloudWatch](https://aws.amazon.com/cloudwatch/) - 10 个自定义指标和 10 个报警
    * [CodeBuild](https://aws.amazon.com/codebuild/) - 每月 100 分钟的构建时间
    * [CodeCommit](https://aws.amazon.com/codecommit/) - 5 名活跃用户，50GB 存储和每月 10000 次请求
    * [CodePipeline](https://aws.amazon.com/codepipeline/) - 每月 1 个活跃管道
    * [DynamoDB](https://aws.amazon.com/dynamodb/) - 25GB NoSQL 数据库
    * [EC2](https://aws.amazon.com/ec2/) - 每月 750 小时 t2.micro 或 t3.micro（12 个月）。每月 100GB 出口
    * [EBS](https://aws.amazon.com/ebs/) - 每月 30GB 的通用 (SSD) 或磁盘(12 个月)
    * [Elastic Load Balancing](https://aws.amazon.com/elasticloadbalancing/) - 每月 750 小时 (12 个月)
    * [RDS](https://aws.amazon.com/rds/) - 每月 750 小时 db.t2.micro、db.t3.micro 或 db.t4g.micro，20GB 通用 (SSD) 存储，20GB 存储备份 (12 个月)
    * [S3](https://aws.amazon.com/s3/) - 5GB 标准对象存储，每月 20K 获取请求和 2K 放置请求（12 个月）
    * [Glacier](https://aws.amazon.com/glacier/) - 10GB 长期对象存储
    * [Lambda](https://aws.amazon.com/lambda/) - 每月 100 万请求
    * [SNS](https://aws.amazon.com/sns/) - 每月 100 万次发布
    * [SES](https://aws.amazon.com/ses/) - 每月 3,000 消息（12 个月）
    * [SQS](https://aws.amazon.com/sqs/) - 每月 100 万消息队列请求
    * 完整详细列表 - https://aws.amazon.com/free/

  * [Microsoft Azure](https://azure.microsoft.com)
    * [虚拟机](https://azure.microsoft.com/services/virtual-machines/) - 1 B1S Linux VM，1 B1S Windows VM (12 个月)
    * [App Service](https://azure.microsoft.com/services/app-service/) - 10 个 Web、移动或 API 应用（每月 60 CPU 分钟）
    * [Functions](https://azure.microsoft.com/services/functions/) - 每月 100 万请求
    * [DevTest Labs](https://azure.microsoft.com/services/devtest-lab/) - 快速、轻便地启用开发测试环境
    * [Active Directory](https://azure.microsoft.com/services/active-directory/) - 500,000 个对象
    * [Active Directory B2C](https://azure.microsoft.com/services/active-directory/external-identities/b2c/) - 每月 50,000 个存储用户
    * [Azure DevOps](https://azure.microsoft.com/services/devops/) - 5 名活跃用户，无限制的私人 Git 存储库
    * [Azure Pipelines](https://azure.microsoft.com/services/devops/pipelines/) — 开源项目为 Linux、macOS 和 Windows 提供 10 个免费并行作业，无限制分钟数
    * [Microsoft IoT Hub](https://azure.microsoft.com/services/iot-hub/) - 每天 8,000 条消息
    * [Load Balancer](https://azure.microsoft.com/services/load-balancer/) - 1 个免费的公共负载均衡 IP (VIP)
    * [Notification Hubs](https://azure.microsoft.com/services/notification-hubs/) - 每月 100 万次推送通知
    * [Bandwidth](https://azure.microsoft.com/pricing/details/bandwidth/) - 15GB 入站(12 个月) & 每月 5GB 出口
    * [Cosmos DB](https://azure.microsoft.com/services/cosmos-db/) - 25GB 的存储和 1000 RUs 的预置吞吐量
    * [Static Web Apps](https://azure.microsoft.com/pricing/details/app-service/static/) — 构建、部署和托管静态应用和无服务器函数，包含免费 SSL、身份验证/授权和自定义域
    * [Storage](https://azure.microsoft.com/services/storage/) - 5GB LRS 文件或 Blob 存储 (12 个月)
    * [Cognitive Services](https://azure.microsoft.com/services/cognitive-services/) - 包含有限交易的免费范围的 AI/ML API（计算机视觉、翻译、面部检测、机器人等）
    * [Cognitive Search](https://azure.microsoft.com/services/search/#features) - 基于 AI 的搜索和索引服务，免费供 10,000 个文档使用
    * [Azure Kubernetes Service](https://azure.microsoft.com/services/kubernetes-service/) - 管理的 Kubernetes 服务，免费集群管理
    * [Event Grid](https://azure.microsoft.com/services/event-grid/) - 每月 10 万个操作
    * 完整详细列表 - https://azure.microsoft.com/free/

  * [Oracle Cloud](https://www.oracle.com/cloud/)
    * 计算
       - 2 个基于 AMD 的计算 VM，每个 1/8 OCPU 和 1 GB 内存
       - 4 个基于 Arm 的 Ampere A1 核心和 24 GB 内存可用作 1 个 VM 或最多 4 个 VM
       - 当被判为空闲时，[实例会被收回](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm#compute__idleinstances)
    * 块存储 - 2 个卷，总共 200 GB（用于计算）
    * 对象存储 - 10 GB
    * 负载均衡器 - 1 个具有 10 Mbps 的实例
    * 数据库 - 2 个数据库，每个 20 GB
    * 监控 - 5 亿个摄入数据点，10 亿个检索数据点
    * 带宽 - 每月 10 TB 出口，x64 基于 VM 的速度限制为 50 Mbps，基于 ARM 的 VM 为 500 Mbps * 核心数
    * 公共 IP - 2 个 IPv4 用于 VM，1 个 IPv4 用于负载均衡器
    * 通知 - 每月 1M 送达选项，每月 1000 封电子邮件
    * 完整详细列表 - https://www.oracle.com/cloud/free/

  * [IBM Cloud](https://www.ibm.com/cloud/free/)
    * 对象存储 - 每月 25GB
    * Cloudant 数据库 - 1 GB 数据存储
    * Db2 数据库 - 100MB 数据存储
    * API Connect - 每月 50,000 个 API 调用
    * 可用性监控 - 每月 300 万个数据点
    * 日志分析 - 每天 500MB 日志
    * 完整详细列表 - https://www.ibm.com/cloud/free/

  * [Cloudflare](https://www.cloudflare.com/)
    * [应用程序服务](https://www.cloudflare.com/plans/) - 免费提供无限数量域的 DNS、DDoS 保护、CDN 以及免费的 SSL、防火墙规则和页面规则、WAF、机器人缓解、自由的不计量速率限制 - 每个域 1 条规则、分析、电子邮件转发
    * [零信任和 SASE](https://www.cloudflare.com/plans/zero-trust-services/) - 最多 50 个用户，24 小时活动日志，三个网络位置
    * [Cloudflare Tunnel](https://www.cloudflare.com/products/tunnel/) - 您可以通过隧道将本地运行的 HTTP 端口暴露到 trycloudflare.com 上随机子域使用 [快速隧道](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/run-tunnel/trycloudflare)，无需账号。更多功能（TCP 隧道、负载均衡、VPN）在 [Zero Trust](https://www.cloudflare.com/products/zero-trust/) 免费计划中。
    * [Workers](https://developers.cloudflare.com/workers/) - 在 Cloudflare 的全球网络上免费部署无服务器代码——每天 100k 请求。
    * [Workers KV](https://developers.cloudflare.com/kv) - 每天 100k 读取请求，每天 1000 写入请求，每天 1000 删除请求，每天 1000 列表请求，1 GB 存储数据
    * [R2](https://developers.cloudflare.com/r2/) - 每月 10 GB，每月 100 万 Class A 操作，每月 1000 万 Class B 操作
    * [D1](https://developers.cloudflare.com/d1/) - 每天读取 500 万行，每天写入 100k 行，1 GB 存储
    * [Pages](https://developers.cloudflare.com/pages/) - 在 Cloudflare 快速、安全的全球网络上开发和部署您的 Web 应用程序。每月 500 个构建，100 个自定义域，集成 SSL，无限制可访问席位，无限制预览部署，以及通过 Cloudflare Workers 集成的全栈能力。
    * [Queues](https://developers.cloudflare.com/queues/) - 每月 100 万次操作
    * [TURN](https://developers.cloudflare.com/calls/turn/) – 每月 1TB 的免费（出站）流量。

**[⬆️ 返回顶部](#table-of-contents)**

## 云管理解决方案

  * [Brainboard](https://www.brainboard.co) - 协作解决方案，旨在以可视化方式构建和管理云基础设施，从头到尾。
  * [Cloud 66](https://www.cloud66.com/) - 适用于个人项目免费的服务（包括一个部署服务器，一个静态网站），Cloud 66 为您提供构建、部署和扩展您的应用程序所需的一切，而无需担心“服务器问题”。
  * [Pulumi](https://www.pulumi.com/) — 现代基础设施即代码平台，允许您使用熟悉的编程语言和工具构建、部署和管理云基础设施。
  * [terraform.io](https://www.terraform.io/) — Terraform Cloud。用于远程状态管理和团队协作的免费版，最多支持 500 个资源。
  * [scalr.com](https://scalr.com/) - Scalr 是一个 Terraform 自动化和协作 (TACO) 产品，致力于提升 Terraform 管理的基础设施和配置的协作与自动化。完全支持 Terraform CLI，OPA 集成，分层配置模型。没有 SSO 税。所有功能均包含在内。每月最多可免费运行 50 次。
  * [deployment.io](https://deployment.io) - Deployment.io帮助开发人员自动化AWS上的部署。在我们的免费层中，开发人员（单一用户）可以无限制地部署静态网站、Web 服务和环境。我们提供每月 20 次作业执行，并在免费层中包含预览和自动部署。

**[⬆️ 返回顶部](#table-of-contents)**

## 源代码存储库

  * [Bitbucket](https://bitbucket.org/) — 无限公共和私有 Git 存储库，最多 5 名用户，并带有 CI/CD 的流水线
  * [chiselapp.com](https://chiselapp.com/) — 无限公共和私有 Fossil 存储库
  * [codebasehq.com](https://www.codebasehq.com/) — 一个免费项目，100 MB 空间，两个用户
  * [Codeberg](https://codeberg.org/) — 无限公共和私有 Git 存储库，供免费和开源项目使用（与无限协作者）。由 [Forgejo](https://forgejo.org/) 提供动力。与 [Codeberg Pages](https://codeberg.page/) 的静态网站托管。与 [Codeberg's CI](https://docs.codeberg.org/ci/) 的 CI/CD 托管。与 [Codeberg Translate](https://translate.codeberg.org/) 的翻译托管。包括包和容器托管、项目管理和问题跟踪。
  * [GitGud](https://gitgud.io) — 无限私有和公共存储库。永久免费。使用 GitLab & Sapphire 提供动力。未提供 CI/CD。
  * [GitHub](https://github.com/) — 无限公共存储库和无限私有存储库（与无限协作者）。包括 CI/CD、开发环境、静态托管、包和容器托管、项目管理和 AI Copilot。
  * [gitlab.com](https://about.gitlab.com/) — 无限公共和私有 Git 存储库，最多 5 名协作者。包括 CI/CD、静态托管、容器注册、项目管理和问题跟踪。
  * [framagit.org](https://framagit.org/) — Framagit 是基于 Gitlab 软件的 Framasoft 软件锻造，支持 CI、静态页面、项目页面和问题跟踪。
  * [heptapod.net](https://foss.heptapod.net/) — Heptapod 是 GitLab Community Edition 的友好分支，支持 Mercurial
  * [ionicframework.com](https://ionicframework.com/appflow) - 开发应用的存储库及工具；您也有ionic存储库
  * [NotABug](https://notabug.org) — NotABug.org 是一个用于自由许可项目的自由软件代码协作平台，基于 Git 的
  * [OSDN](https://osdn.net/) - OSDN.net 是一个针对开源软件开发人员的免费服务，提供 SVN/Git/Mercurial/Bazaar/CVS 存储库。
  * [Pagure.io](https://pagure.io) — Pagure.io 是一个免费开源软件代码协作平台，供 FOSS 许可项目使用，基于 Git
  * [perforce.com](https://www.perforce.com/products/helix-teamhub) — 免费 1GB 云存储和 Git、Mercurial 或 SVN 存储库。
  * [pijul.com](https://pijul.com/) - 无限免费开源分布式版本控制系统。其独特特性基于健全的补丁理论，使学习、使用和分发变得简单。解决了 git/hg/svn/darcs 的许多问题。
  * [plasticscm.com](https://plasticscm.com/) — 个人、开源和非营利组织免费
  * [projectlocker.com](https://projectlocker.com) — 一个免费的私有项目（Git 和 Subversion），空间为 50 MB
  * [RocketGit](https://rocketgit.com) — 基于 Git 的存储库托管。无限公共和私有存储库。
  * [savannah.gnu.org](https://savannah.gnu.org/) - 为自由软件项目（GNU 项目）提供协作软件开发管理系统
  * [savannah.nongnu.org](https://savannah.nongnu.org/) - 为自由软件项目（非 GNU 项目）提供协作软件开发管理系统

**[⬆️ 返回顶部](#table-of-contents)**

## API、数据和机器学习

  * [JSONGrid](https://jsongrid.com) - 免费工具可视化、编辑、过滤复杂的 JSON 数据为美丽的表格网格。通过链接保存和共享 JSON 数据。
  * [Zerosheets](https://zerosheets.com) - 将您的 Google 表格转换为强大的 API，快速开发原型、网站、应用等。每月可免费使用 500 次请求。
  * [IP.City](https://ip.city) — 每天 100 次免费 IP 地理位置请求
  * [Abstract API](https://www.abstractapi.com) — 各种用例的 API 套件，包括 IP 地理定位、性别检测或电子邮件验证。
  * [Apify](https://www.apify.com/) — 网络抓取和自动化平台，可以为任何网站创建 API 并提取数据。现成的抓取器、集成代理和自定义解决方案。包含每月 5 美元的平台积分的免费套餐。
  * [APITemplate.io](https://apitemplate.io) - 使用简单的 API 或 Zapier 和 Airtable 等自动化工具自动生成图像和 PDF 文档。不需要 CSS/HTML。免费计划每月提供 50 张图像和 3 个模板。
  * [APIToolkit.io](https://apitoolkit.io) - 了解 API 和后端中发生的情况所需的所有工具。自动 API 合同验证和监控。免费计划涵盖每月最多 20,000 次请求的服务器。
  * [APIVerve](https://apiverve.com) - 免费即时访问 120 多个 API，旨在提供高质量、一致性和可靠性。免费计划覆盖每月最多 50 个 API 令牌。
  * [Arize AI](https://arize.com/) - 针对模型监控和根本原因分析等问题的机器学习可观察性。免费最多两个模型。
  * [Atlas toolkit](https://atlastk.org/) - 轻量级库，用于开发可即时访问的单页 Web 应用程序。提供 Java、Node.js、Perl、Python 和 Ruby 的支持。
  * [Beeceptor](https://beeceptor.com) - 在几秒钟内模拟 REST API，虚假 API 响应等。每天 50 个请求，公开仪表板，开放端点（任何拥有仪表板链接的人都可以查看提交和答案）。
  * [bigml.com](https://bigml.com/) — 托管的机器学习算法。开发中没有限制的免费任务，限制为每个任务 16MB 数据。
  * [Browse AI](https://www.browse.ai) — 提取和监控 Web 上的数据。每月 50 次免费积分。
  * [BrowserCat](https://www.browsercat.com) - 自动化、抓取、AI 代理 Web 访问、图像/PDF 生成等的无头浏览器 API。提供每月 1k 请求的免费计划。
  * [Bruzu](https://bruzu.com/) — 自动化图像生产。通过 API、集成或无代码表单生成大量图像变体。API 免费且带水印。
  * [Calendarific](https://calendarific.com) - 企业级公共假期 API 服务，覆盖 200 多个国家。免费计划包括每月 1,000 次调用。
  * [Canopy](https://www.canopyapi.co/) - 亚马逊.com 的产品、搜索和分类数据的 GraphQL API。免费计划包括每月 100 次调用。
  * [Clarifai](https://www.clarifai.com) — 用于自定义面部识别和检测的图像 API。能够训练 AI 模型。免费计划每月有 5,000 次调用。
  * [Cloudmersive](https://cloudmersive.com/) — 实用程序 API 平台，完全访问广泛的 API 库，包括文档转换、病毒扫描等，每月 800 次调用。
  * [Colaboratory](https://colab.research.google.com) — 提供 Nvidia Tesla K80 GPU 的免费基于 Web 的 Python 笔记本环境。
  * [Collect2](https://collect2.com) — 创建 API 端点以测试、自动化和连接 Webhook。免费计划允许两个数据集、2000 条记录、一个转发器和一个警报。
  * [CometML](https://www.comet.com/site/) - 用于实验跟踪、模型生产管理、模型注册和完整数据血缘的 MLOps 平台，覆盖从训练到生产的工作流程。个人和学术用户免费。
  * [Commerce Layer](https://commercelayer.io) - 可组成的商务 API，可以从任何前端构建、下达和管理订单。开发者计划允许每月 100 个订单和最多 1,000 个 SKU 的免费使用。
  * [Conversion Tools](https://conversiontools.io/) — 文档、图像、视频、音频和电子书的在线文件转换器。提供 REST API。支持节点.js、PHP、Python 文件。支持高达 50 GB 的文件（付费计划）。免费套餐受到文件大小和每天转换次数的限制。
  * [Country-State-City Microservice API](https://country-state-city.rebuscando.info/) - API 和微服务提供多种信息，包括国家、地区、省份、城市、邮政编码等。免费套餐每日最多可提供 100 次请求。
  * [Coupler](https://www.coupler.io/) - 数据集成工具，可在应用程序之间同步。可以创建实时仪表板和报告，转换和操纵值，并收集和备份见解。免费计划拥有无限用户，每月 100 次运行，1000 条每月行数和无限集成。
  * [CraftMyPDF](https://craftmypdf.com) - 从可重用模板自动生成 PDF 文档，带有拖放编辑器和简单 API。免费计划每月提供 100 个 PDF 和 3 个模板。
  * [CurlHub](https://curlhub.io) — 用于检查和调试 API 调用的代理服务。免费计划包括每月 10,000 次请求。
  * [CurrencyScoop](https://currencyscoop.com) - 金融科技应用程序的实时货币数据 API。免费计划包括每月 5,000 次调用。
  * [Cube](https://cube.dev/) - Cube 帮助数据工程师和应用开发人员访问现代数据存储中的数据，将其组织成一致的定义，并将其交付给每个应用程序。使用 Cube Cloud 是使用 Cube 的最快方式，Cube Cloud 均提供免费层，每月 1GB 数据通过。
  * [Data Dead Drop](https://datadeaddrop.com) - 简单且免费的文件共享。数据在访问后自毁。通过浏览器或您最喜欢的命令行客户端上传和下载数据。
  * [Data Fetcher](https://datafetcher.com) - 在任何应用程序或 API 之间以无代码的方式连接 Airtable。类似于 Postman 的界面，用于在 Airtable 中运行 API 请求。与数十个应用程序预构建集成。免费计划包括每月 100 次运行。
  * [Dataimporter.io](https://www.dataimporter.io) - 用于连接、清理和导入数据到 Salesforce 的工具。免费计划每月最多包括 20,000 条记录。
  * [Datalore](https://datalore.jetbrains.com) - Jetbrains 的 Python 笔记本。每月包括 10 GB 存储和 120 小时运行时间。
  * [Data Miner](https://dataminer.io/) - Google Chrome 和 MS Edge 的浏览器扩展，用于从网页提取数据到 CSV 或 Excel 中。免费计划每月为您提供 500 页。
  * [Datapane](https://datapane.com) - 用于在 Python 中构建交互式报告的 API，并将 Python 脚本和 Jupyter 笔记本作为自助工具进行部署。
  * [DB-IP](https://db-ip.com/api/free) - 免费的 IP 地理位置 API，每个 IP 每天提供 1000 次请求。根据 CC-BY 4.0 许可，lite 数据库也免费。
  * [DB Designer](https://www.dbdesigner.net/) — 基于云的数据库模式设计和建模工具，提供两个数据库模型和每个模型 10 个表的免费入门计划。
  * [DeepAR](https://developer.deepar.ai) — 适用于任何平台的增强现实面部过滤器，仅需一个 SDK。免费计划每月提供最多 10 个活跃用户 (MAU) 并跟踪最多 4 个面孔。
  * [Deepnote](https://deepnote.com) - 新的数据科学笔记本。与 Jupyter 兼容，在云中实时协作和运行。免费层包括无限个人项目，最多 750 小时的标准硬件和最多 3 位编辑员的团队。
  * [Diggernaut](https://www.diggernaut.com/) — 基于云的网站抓取和数据提取平台，用于将任何网站转变为数据集，或将其作为 API 进行处理。免费计划每月包括 5K 页请求。
  * [Disease.sh](https://disease.sh/) — 提供用于构建与 Covid-19 相关的有用应用程序的准确数据的免费 API。
  * [Doczilla](https://www.doczilla.app/) — SaaS API 使能够直接从 HTML/CSS/JS 代码生成屏幕截图或 PDF。免费计划每月允许 250 个文档。
  * [Doppio](https://doppio.sh/) — 管理的 API 以使用顶级渲染技术生成和私有存储 PDF 和屏幕截图。免费计划每月允许 400 个 PDF 和屏幕截图。
  * [dreamfactory.com](https://dreamfactory.com/) — 开源 REST API 后端，用于移动、Web 和 IoT 应用程序。连接任何 SQL/NoSQL 数据库、文件存储系统或外部服务，便会立即创建全面的 REST API 平台，带有实时文档和用户管理。
  * [DynamicDocs](https://advicement.io) - 基于 LaTeX 模板生成 PDF 文档的 JSON 到 PDF API。免费计划每月允许 50 次 API 调用以及访问模板库。
  * [Efemarai](https://efemarai.com) - 用于 ML 模型和数据的测试和调试平台。可视化任何计算图。每月提供 30 次调试会话的免费计划。
  * [ExtendsClass](https://extendsclass.com/rest-client-online.html) - 免费的基于 Web 的 HTTP 客户端，用于发送 HTTP 请求。
  * [Export SDK](https://exportsdk.com) - PDF 生成器 API，配备拖放模板编辑器，提供 SDK 和无代码集成。免费计划每月提供 250 页，允许无限用户和 3 个模板。
  * [Fern](https://buildwithfern.com) - 使用您的 API 定义生成流行语言的 SDK，并生成 API 参考文档网页。将 Markdown 页面添加到您的 API 参考中，并使用 Fern 托管它们，以实现全面的文档解决方案。完全支持 OpenAPI。
  * [file.coffee](https://file.coffee/) - 一个可以存储高达 15MB/文件的平台 (30/MB 文件带帐户)。
  * [FraudLabs Pro](https://www.fraudlabspro.com) — 对信用卡支付欺诈订单交易进行审查。此 REST API 将根据订单的输入参数检测所有可能的欺诈特征。 免费微型计划每月 500 次交易。
  * [Geekflare API](https://geekflare.com/api) - Geekflare API 让您截屏、审核网站、TLS 扫描、DNS 查询、TTFB 测试等。免费计划提供 3,000 次 API 请求。
  * [GeoCod](https://geocod.xyz) — 免费地理编码 API：将邮政地址转换为地理坐标或将地理坐标转换为邮政地址（反向地理编码）。
  * [GeoDataSource](https://www.geodatasource.com) — 位置搜索服务，使用经纬度坐标查找城市名称。该 API 免费查询高达每月 500 次。
  * [Geolocated.io](https://geolocated.io) — IP 地理位置 API，提供多大洲服务器，提供永远免费的计划，每月 60000 次请求，供爱好者使用。
  * [Glitterly](https://glitterly.app/) - 程序化生成动态图像。RESTful API 和无需编程的集成。免费套餐每月提供 50 张图像和 5 个模板。
  * [GoodData](https://www.gooddata.com/) - 数据即服务 - 创建交互式和直观的仪表板。免费套餐包含五个工作区和每个工作区 100 MB。
  * [Hex](https://hex.tech/) - 适用于笔记本、数据应用程序和知识库的协作数据平台。Free community version with up to 3 authors and five projects. One compute profile per author with 4GB RAM.
  * [Hook0](https://www.hook0.com/) - Hook0 是一个开源的 Webhooks 即服务 (WaaS)，使在线产品能够轻松提供 Webhooks。每月转发最多 3000 次事件，7 天的历史保留期免费。
  * [Hoppscotch](https://hoppscotch.io) - 免费、快速、美观的 API 请求构建器。
  * [Invantive Cloud](https://cloud.invantive.com/) — 访问超过 70 个 (云) 平台，例如 Exact Online、Twinfield、ActiveCampaign 或 Visma，使用 Invantive SQL 或 OData4 (通常是 Power BI 或 Power Query)。包括数据复制和交换。为开发人员和实施顾问提供免费计划。针对特定平台的免费计划，数据量有限制。
  * [ipaddress.sh](https://ipaddress.sh) — 一项简单的服务，可以以不同的 [格式](https://about.ipaddress.sh/) 获取公共 IP 地址。
  * [IP info](https://ipinfo.io/) — 快速、准确且免费的（每月最多 50k）IP 地址数据 API。提供有关地理定位、公司、运营商、IP 范围、域名、滥用联系等的详细信息。所有付费 API 都可以免费试用。
  * [ipapi](https://ipapi.co/) - 由 Kloudend, Inc. 提供的 IP 地址位置 API - 一种可靠的地理位置 API，建立在 AWS 基础上，受到财富 500 大公司的信任。免费套餐提供每月 30k 次查找 (1k/day)，无须注册。
  * [SAP API](https://help.sap.com/docs/SAP_API_Management/3bb0b24051df4f51a40daf2c3c9b3f5d.html?locale=en) - 使用 SAP Cloud Platform API Management 管理 API。
  * [dataflow.dev](https://dataflow.dev/) — 用于简化数据集成并执行现代数据处理任务的 API。通过 API 请求与数据集成、处理和流式传输紧密协调。每月高达 10,000 次请求和 500 GB 的日常使用。
  * [dataflow ](http://dataflow.com)
  * [AI Labs](https://ailabs.com/) — 使用这个 AI 实验室为任何项目提供无缝 API。[进入 API](https://ailabs.com/api)。

**[⬆️ 返回顶部](#table-of-contents)**

## 参与

请参与，为这份列表贡献您知道的免费服务，我们希望持续为开发者们提供帮助！如果您知道任何服务失效或需要更新的信息，请通过 [GitHub 提交](https://github.com/ripienaar/free-for-dev) 反馈。

**谢谢！**
