# free-for.dev

Developers and Open Source authors now have a massive amount of services offering free tiers, but it can be hard to find them all to make informed decisions.

This is a list of software (SaaS, PaaS, IaaS, etc.) and other offerings that have free tiers for developers.

The scope of this particular list is limited to things that infrastructure developers (System Administrator, DevOps Practitioners, etc.) are likely to find useful. We love all the free services out there, but it would be good to keep it on topic. It's a bit of a grey line at times so this is a bit opinionated; do not be offended if I do not accept your contribution.

This list is the result of Pull Requests, reviews, ideas and work done by 900+ people. You too can help by sending [Pull Requests](https://github.com/ripienaar/free-for-dev) to add more services or by remove ones whose offerings have changed or been retired.

*NOTE:* This list is only for as-a-Service offerings, not for self-hosted software. For a service to be eligible it has to offer a free tier and not just a free trial. If the free tier is time-bucketed it has to be for at least a year. We also consider the free tier from a security perspective, so SSO is fine but I will not accept services that restrict TLS to paid-only tiers.

Table of Contents
=================

   * [Major Cloud Providers' Always-Free Limits](#major-cloud-providers)
   * [Analytics, Events and Statistics](#analytics-events-and-statistics)
   * [APIs, Data and ML](#apis-data-and-ml)
   * [Artifact Repos](#artifact-repos)
   * [BaaS](#baas)
   * [CDN and Protection](#cdn-and-protection)
   * [CI and CD](#ci-and-cd)
   * [CMS](#cms)
   * [Code Quality](#code-quality)
   * [Code Search and Browsing](#code-search-and-browsing)
   * [Crash and Exception Handling](#crash-and-exception-handling)
   * [Data Visualization on Maps](#data-visualization-on-maps)
   * [DBaaS](#dbaas)
   * [Design and UI](#design-and-ui)
   * [Dev Blogging Sites](#dev-blogging-sites)
   * [DNS](#dns)
   * [Docker Related](#docker-related)
   * [Email](#email)
   * [Font](#font)
   * [Forms](#forms)
   * [IaaS](#iaas)
   * [IDE and Code Editing](#ide-and-code-editing)
   * [International Mobile Number Verification API and SDK](#international-mobile-number-verification-api-and-sdk)
   * [Issue Tracking and Project Management](#issue-tracking-and-project-management)
   * [Log Management](#log-management)
   * [Management Systems](#management-system)
   * [Messaging and Streaming](#messaging)
   * [Miscellaneous](#miscellaneous)
   * [Monitoring](#monitoring)
   * [PaaS](#paas)
   * [Package Build System](#package-build-system)
   * [Payment and Billing Integration](#payment-and-billing-integration)
   * [Screenshot APIs](#screenshot-apis)
   * [Search](#search)
   * [Security and PKI](#security-and-pki)
   * [Source Code Repos](#source-code-repos)
   * [Storage and Media Processing](#storage-and-media-processing)
   * [STUN, WebRTC, Web Socket Servers and Other Routers](#stun-webrtc-web-socket-servers-and-other-routers)
   * [Testing](#testing)
   * [Tools for Teams and Collaboration](#tools-for-teams-and-collaboration)
   * [Translation Management](#translation-management)
   * [Vagrant Related](#vagrant-related)
   * [Visitor Session Recording](#visitor-session-recording)
   * [Web Hosting](#web-hosting)
   * [Commenting Platforms](#commenting-platforms)
   * [Browser based hardware emulation](#browser-based-hardware-emulation-written-in-javascript)
   * [Other Free Resources](#other-free-resources)

## Major Cloud Providers

  * [Google Cloud Platform](https://cloud.google.com)
    * App Engine - 28 frontend instance hours per day, 9 backend instance hours per day
    * Cloud Firestore - 1GB storage, 50,000 reads, 20,000 writes, 20,000 deletes per day
    * Compute Engine - 1 non-preemptible f1-micro, 30GB HDD, 5GB snapshot storage (restricted to certain regions), 1 GB network egress from North America to all region destinations (excluding China and Australia) per month
    * Cloud Storage - 5GB, 1GB network egress
    * Cloud Shell - Web-based Linux shell/basic IDE with 5GB of persistent storage. 60 hours limit per week
    * Cloud Pub/Sub - 10GB of messages per month
    * Cloud Functions - 2 million invocations per month (includes both background and HTTP invocations)
    * Cloud Run - 2 million requests per month, 360,000 GB-seconds memory, 180,000 vCPU-seconds of compute time, 1 GB network egress from North America per month
    * Google Kubernetes Engine - No cluster management fee for one zonal cluster. Each user node is charged at standard Compute Engine pricing
    * BigQuery - 1 TB of querying per month, 10 GB of storage each month
    * Cloud Build - 120 build-minutes per day
    * Cloud Source Repositories - Up to 5 Users, 50 GB Storage, 50 GB Egress
    * Full, detailed list - https://cloud.google.com/free

  * [Amazon Web Services](https://aws.amazon.com)
    * Amazon DynamoDB - 25GB NoSQL DB
    * Amazon Lambda - 1 Million requests per month
    * Amazon SNS - 1 million publishes per month
    * Amazon Cloudwatch - 10 custom metrics and 10 alarms
    * Amazon Glacier - 10GB long-term object storage
    * Amazon SQS - 1 million messaging queue requests
    * Amazon CodeBuild - 100min of build time per month
    * Amazon Code Commit - 5 active users per month
    * Amazon Code Pipeline - 1 active pipeline per month
    * Full, detailed list - https://aws.amazon.com/free/

  * [Microsoft Azure](https://azure.microsoft.com)
    * [Virtual Machines](https://azure.microsoft.com/services/virtual-machines/) - 1 B1S Linux VM, 1 B1S Windows VM
    * [App Service](https://azure.microsoft.com/services/app-service/) - 10 web, mobile or API apps
    * [Functions](https://azure.microsoft.com/services/functions/) - 1 million requests per month
    * [DevTest Labs](https://azure.microsoft.com/services/devtest-lab/) - Enable fast, easy, and lean dev-test environments
    * [Active Directory](https://azure.microsoft.com/services/active-directory/) - 500,000 objects
    * [Active Directory B2C](https://azure.microsoft.com/services/active-directory/external-identities/b2c/) - 50,000 monthly stored users
    * [Azure DevOps](https://azure.microsoft.com/services/devops/) - 5 active users, unlimited private Git repos
    * [Azure Pipelines](https://azure.microsoft.com/services/devops/pipelines/) — 10 free parallel jobs with unlimited minutes for open source for Linux, macOS, and Windows
    * [Microsoft IoT Hub](https://azure.microsoft.com/services/iot-hub/) - 8,000 messages per day
    * [Load Balancer](https://azure.microsoft.com/services/load-balancer/) - 1 free public load balanced IP (VIP)
    * [Notification Hubs](https://azure.microsoft.com/services/notification-hubs/) - 1 million push notifications
    * [Bandwidth](https://azure.microsoft.com/pricing/details/bandwidth/) - 5GB egress per month
    * [Cosmos DB](https://azure.microsoft.com/services/cosmos-db/) - 5GB storage and 400 RUs of provisioned throughput
    * [Static Web Apps](https://azure.microsoft.com/pricing/details/app-service/static/) — Build, deploy and host static apps and serverless functions, with free SSL, Authentication/Authorization and custom domains
    * [Storage](https://azure.microsoft.com/services/storage/) - 5GB LRS File or Blob storage
    * [Cognitive Services](https://azure.microsoft.com/services/cognitive-services/) - AI/ML APIs (Computer Vision, Translator, Face detection, Bots...) with free tier including limited transactions
    * [Cognitive Search](https://azure.microsoft.com/services/search/#features) - AI-based search and indexation service, free for 10,000 documents
    * [Azure Kubernetes Service](https://azure.microsoft.com/services/kubernetes-service/) - Managed Kubernetes service, free cluster management
    * [Event Grid](https://azure.microsoft.com/services/event-grid/) - 100K ops/month
    * Full, detailed list - [https://azure.microsoft.com/free/](https://azure.microsoft.com/free/)

  * [Oracle Cloud](https://www.oracle.com/cloud/)
    * Compute - 2 VM.Standard.E2.1.Micro 1GB RAM
    * Block Volume - 2 volumes, 100 GB total (used for compute)
    * Object Storage - 10 GB
    * Load balancer - 1 instance with 10 Mbps
    * Databases - 2 DBs, 20 GB each
    * Monitoring - 500 million ingestion datapoints, 1 billion retrieval datapoints
    * Bandwidth - 10TB egress per month, speed limited to 5Mbps
    * Notifications - 1 million delivery options per month, 1000 emails sent per month
    * Full, detailed list - https://www.oracle.com/cloud/free/

  * [IBM Cloud](https://www.ibm.com/cloud/free/)
    * Cloud Functions - 5 million executions per month
    * Object Storage - 25GB per month
    * Cloudant database - 1 GB of data storage
    * Db2 database - 100MB of data storage
    * API Connect - 50,000 API calls per month
    * Availability Monitoring - 3 million data points per month
    * Log Analysis - 500MB of daily log
    * Full, detailed list - https://www.ibm.com/cloud/free/

## Source Code Repos

  * [bitbucket.org](https://bitbucket.org/) — Unlimited public and private Git repos for up to 5 users with Pipelines for CI/CD
  * [chiselapp.com](http://chiselapp.com/) — Unlimited public and private Fossil repositories
  * [codebasehq.com](https://www.codebasehq.com/) — One free project with 100 MB space and 2 users
  * [codeberg.org](https://codeberg.org/) - Unlimited public and private Git repos
  * [gitea.com](https://www.gitea.com/) - Unlimited public and private Git repos
  * [GitGud](https://gitgud.io) — Unlimited private and public repositories. Free forever. Powered by GitLab & Sapphire. CI/CD not provided.
  * [github.com](https://github.com/) — Unlimited public repositories and unlimited private repositories (with unlimited collaborators). Apart from this some other free services(there are much more but we list the main ones here) provided are :
       - [CI/CD](https://github.com/features/actions)(Free for Public Repos, 2000 min/month for private repos free) 
       - [Static Website Hosting](https://pages.github.com) (Free for Public Repos)  
       - [Package Hosting & Container Registry](https://github.com/features/packages) (Free for public repos,500 MB storage & 1GB bandwidth outside CI/CD free for private repos)
       - Project Management & Issue Tracking.
  * [gitlab.com](https://about.gitlab.com/) — Unlimited public and private Git repos with unlimited collaborators. Also offers the following features :
       - [CI/CD](https://about.gitlab.com/product/continuous-integration) (Free for Public Repos, 400 mins/month for private repos)
       - Static Sites with [GitLab Pages](https://about.gitlab.com/product/pages).
       - Container Registry with 10 GB limit per repo.
       - Project Management & Issue Tracking.
  * [heptapod.net](https://foss.heptapod.net/) — Heptapod is a friendly fork of GitLab Community Edition providing support for Mercurial
  * [ionicframework.com](https://ionicframework.com/appflow) - Repo and tools to develop applications with Ionic, also you have an ionic repo
  * [NotABug](https://notabug.org) — NotABug.org is a free-software code collaboration platform for freely licensed projects, Git-based
  * [Pagure.io](https://pagure.io) — Pagure.io is a free and open source software code collaboration platform for FOSS-licensed projects, Git-based
  * [perforce.com](https://www.perforce.com/products/helix-teamhub) — Free 1GB Cloud and  Git, Mercurial, or SVN repositories.
  * [pijul.com](https://pijul.com/) - Unlimited free and open source distributed version control system. Its distinctive feature is to be based on a sound theory of patches, which makes it easy to learn and use, and really distributed. Solves many problems of git/hg/svn/darcs.
  * [plasticscm.com](https://plasticscm.com/) — Free for individuals, OSS and nonprofit organizations
  * [projectlocker.com](https://projectlocker.com) — One free private project (Git and Subversion) with 50 MB space
  * [RocketGit](https://rocketgit.com) — Repository Hosting based on Git. Unlimited Public & Private repositories.
  * [savannah.gnu.org](https://savannah.gnu.org/) - Serves as a collaborative software development management system for free Software projects (for GNU Projects)
  * [savannah.nongnu.org](https://savannah.nongnu.org/) - Serves as a collaborative software development management system for free Software projects (for non-GNU projects)

## APIs, Data and ML

  * [IP.City](https://ip.city) — 100 free IP geolocation requests per day
  * [Abstract API](https://www.abstractapi.com) — API suite for a variety of use cases including IP geolocation, gender detection or even email validation.
  * [algorithmia.com](https://algorithmia.com/) — Host algorithms for free. Includes free monthly allowance for running algorithms. Now with CLI support.
  * [Apify](https://www.apify.com/) — Web scraping and automation platform that lets you create an API extracting websites data. Free tier with 10k monthly crawls and 7 days data retention.
  * [API Mocha](https://apimocha.com) - Completely free online API mocking for testing and prototyping.  Make up to 500 requests per day, fully customizable API responses, download mock rules as a Postman collection.
  * [APITemplate.io](https://apitemplate.io) - Auto-generate images and PDF documents with a simple API or automation tools like Zapier & Airtable. No CSS/HTML required. Free plan comes with 50 images/month and 3 templates.
  * [Atlas toolkit](https://atlastk.org/) - Lightweight library to develop single-page web applications that are instantly accessible. Available for Java, Node.js, Perl, Python and Ruby.
  * [Beeceptor](https://beeceptor.com) - Mock a rest API in seconds, fake API response and much more. Free 50 requests per day, public dashboard, open endpoints (anyone having link to the dashboard can view requests and responses).
  * [bigml.com](https://bigml.com/) — Hosted machine learning algorithms. Unlimited free tasks for development, limit of 16 MB data/task.
  * [Calendarific](https://calendarific.com) - Enterprise-grade Public holiday API service for over 200 countries. Free plan includes 1000 calls per month.
  * [Clarifai](https://www.clarifai.com) — Image API for custom face recognition and detection. Able to train AI models. Free plan has 5000 calls per month.
  * [Cloudmersive](https://cloudmersive.com/) — Utility API platform with full access to expansive API Library including Document Conversion, Virus Scanning, and more with 800 calls/month.
  * [Colaboratory](https://colab.research.google.com) — Free web-based Python notebook environment with Nvidia Tesla K80 GPU.
  * [Collect2](https://collect2.com) — Create an API endpoint to test, automate, and connect webhooks. Free plan allows for two datasets, 2000 records, 1 forwarder, and 1 alert.
  * [Conversion Tools](https://conversiontools.io/) - Online File Converter for documents, images, video, audio, eBooks. REST API is available. Libraries for Node.js, PHP, Python. Support files up to 50 GB (for paid plans). Free tier is limited by file size and number of conversions per day.
  * [CurlHub](https://curlhub.io) — Proxy service for inspecting and debugging API calls. Free plan includes 10,000 requests per month.
  * [CurrencyScoop](https://currencyscoop.com) - Realtime currency data API for fintech apps. Free plan includes 5000 calls per month.
  * [Datapane](https://datapane.com) - API for building interactive reports in Python and deploying Python scripts and Jupyter Notebooks as self-service tools.
  * [DB Designer](https://www.dbdesigner.net/) — Cloud based Database schema design and modeling tool with a free starter plan of 2 Database models and 10 tables per model.
  * [DeepAR](https://developer.deepar.ai) — Augmented reality face filters for any platform with one SDK. Free plan provides up to 10 monthly active users (MAU) and tracking up to 4 faces
  * [Diggernaut](https://www.diggernaut.com/) — Cloud based web scraping and data extraction platform for turning any website to the dataset or to work with it as with an API. Free plan includes 5K page requests monthly.
  * [Disease.sh](https://disease.sh/) — A free API providing accurate data for building the Covid-19 related useful Apps.
  * [dominodatalab.com](https://www.dominodatalab.com) — Data science with support for Python, R, Spark, Hadoop, MATLAB and others.
  * [dreamfactory.com](https://dreamfactory.com/) — Open source REST API backend for mobile, web, and IoT applications. Hook up any SQL/NoSQL database, file storage system, or external service and it instantly creates a comprehensive REST API platform with live documentation, user management,...
  * [Efemarai](https://efemarai.com) - Testing and debugging platform for ML models and data. Visualize any computational graph. Free 30 debugging sessions per month for developers.
  * [ETF Data API](https://etf-data.com/) - Quality European ETF, ETN and ETC data, updated daily. The API offers complete overview including sector, country, factor, dividend yield and valuations. Additionally basic information such as domicile, followed index, asset class, fee, currency, replication method, distribution type and frequency. 50 free API calls per day.
  * [ExtendsClass](https://extendsclass.com/rest-client-online.html) - Free web-based HTTP client to send HTTP requests.
  * [FraudLabs Pro](https://www.fraudlabspro.com) — Screen an order transaction for credit card payment fraud. This REST API will detect all possible fraud traits based on the input parameters of an order. Free Micro plan has 500 transactions per month.
  * [FreeGeoIP.app](https://freegeoip.app/) - Completely free Geo IP information (JSON, CSV, XML). No registration required, 15000 queries per hour rate limit.
  * [GeoDataSource](https://www.geodatasource.com) — Location search service lookup for city name by using latitude and longitude coordinate. Free API queries up to 500 times per month.
  * [Hookbin](https://hookbin.com/) - Create unique (public or private) endpoints to collect, parse, and inspect HTTP requests. Inspect headers, body, query strings, cookies, uploaded files, etc. Useful for testing/inspecting webhook. Similar to RequestBin, and Webhook.site.
  * [Hoppscotch](https://hoppscotch.io) - A free, fast, and beautiful API request builder.
  * [Invantive Cloud](https://cloud.invantive.com/) — Access over 70 (cloud)platforms such as Exact Online, Twinfield, ActiveCampaign or Visma using Invantive SQL or OData4 (typically Power BI or Power Query). Includes data replication and exchange. Free plan for developers and implementation consultants. Free for specific platforms with limitations in data volumes.
  * [IP Geolocation](https://ipgeolocation.io/) — IP Geolocation API - Forever free plan for developers with 30k requests per month (1k/day) limit.
  * [IP Geolocation API](https://www.abstractapi.com/ip-geolocation-api) — IP Geolocation API from Abstract - Extensive free plan allowing 200,000 requests per month.
  * [IP2Location](https://www.ip2location.com) — Freemium IP geolocation service. LITE database is available for free download. Import the database in server and perform local query to determine city, coordinates and ISP information.
  * [ipapi](https://ipapi.co/) - IP Address Location API by Kloudend, Inc - A reliable geolocation API, built on AWS, trusted by Fortune 500. Free tier offers 30k lookups/month (1k/day) without signup. Contact us for a higher limit trial plan.
  * [IPinfo](https://ipinfo.io/) — Fast, accurate, and free (up to 100k/month) IP address data API. Offers APIs with details on geolocation, companies, carriers, IP ranges, domains, abuse contacts, and more. All paid APIs can be trialed for free.
  * [IPList](https://www.iplist.cc) — Lookup details about any IP address, such as Geo IP information, tor addresses, hostnames and ASN details. Free for personal and business users.
  * [BigDataCloud](https://www.bigdatacloud.com/) - Provides fast, accurate and free (Unlimited or up to 10K-50K/month) APIs for modern web like IP Geolocation, Reverse Geocoding, Networking Insights, Email and Phone Validation, Client Info and more.
  * [IPTrace](https://iptrace.io) — An embarrassingly simple API that provides reliable and useful IP geolocation data for your business.
  * [JSON IP](https://getjsonip.com) — Returns the Public IP address of the client it is requested from. No registration required for free tier. Using CORS data can be requested using client side JS directly from browser. Useful for services monitoring change in client and server IPs. Unlimited Requests.
  * [konghq.com/](https://konghq.com/) — API Marketplace and powerful tools for private and public APIs. With the free tier, some features are limited such as monitoring, alerting and support.
  * [Kreya](https://kreya.app) — Free gRPC GUI client to call and test gRPC APIs. Can import gRPC APIs via server reflection.
  * [MailboxValidator](https://www.mailboxvalidator.com) — Email verification service using real mail server connection to confirm valid email. Free API plan has 300 verifications per month.
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities or screenshots as a service. 100 reqs/day every day free.
  * [monkeylearn.com](https://monkeylearn.com/) — Text analysis with machine learning, free 300 queries/month.
  * [MockAPI](https://www.mockapi.io/) — MockAPI is a simple tool that lets you easily mock up APIs, generate custom data, and preform operations on it using RESTful interface. MockAPI is meant to be used as a prototyping/testing/learning tool. 1 project/50 resources per project for free.
  * [microenv.com](https://microenv.com) —  Create fake REST API for developers with possibility to generate code and app in docker container.
  * [News API](https://newsapi.org) — Search news on the web with code, get JSON results. Developers get 3,000 queries free each month.
  * [OCR.Space](https://ocr.space/) — An OCR API which parses image and pdf files returning the text results in JSON format. 25,000 requests per month free.
  * [OpenAPI3 Designer](https://openapidesigner.com/) — Visually create Open API 3 definitions for free.
  * [parsehub.com](https://parsehub.com/) — Extract data from dynamic sites, turn dynamic websites into APIs, 5 projects free.
  * [Pixela](https://pixe.la/) - Free daystream database service. All operations are performed by API. Visualization with heat maps and line graphs is also possible.
  * [Postbacks](https://postbacks.io/) - Request HTTP callbacks for a later time. 8,000 free requests on signup.
  * [Postman](https://postman.com) — Simplify workflows and create better APIs – faster – with Postman, a collaboration platform for API development. Use the Postman App for free forever. Postman cloud features are also free forever with certain limits.
  * [ProxyCrawl](https://proxycrawl.com/) — Crawl and scrape websites without the need of proxies, infrastructure or browsers. We solve captchas for you and prevent you being blocked. The first 1000 calls are free of charge.
  * [QuickMocker](https://quickmocker.com/) — Manage online fake API endpoints under your own subdomain, forward requests to localhost URL for webhooks development and testing, use RegExp and multiple HTTP methods for URL path, prioritize endpoints, more than 100 shortcodes (dynamic or fake response values) for response templating, import from OpenAPI (Swagger) Specifications in JSON format, proxy requests, restrict endpoint by IP address and authorization header. Free account provides 1 random subdomain, 10 endpoints, 5 RegExp URL paths, 50 shortcodes per endpoint, 100 requests per day, 50 history records in requests log.
  * [RequestBin.com](https://requestbin.com) — Create a free endpoint to which you can send HTTP requests. Any HTTP requests sent to that endpoint will be recorded with the associated payload and headers so you can observe requests from webhooks and other services.
  * [restlet.com](https://restlet.com/products/apispark/) — APISpark enables any API, application or data owner to become an API provider in minutes via an intuitive browser interface.
  * [Roboflow](https://roboflow.com) - create and deploy a custom computer vision model with no prior machine learning experience required. Free tier includes up to 1,000 free source images.
  * [ROBOHASH](https://robohash.org/) - Web service to generate unique (cool :) images from any text.
  * [Scraper.AI](https://scraper.ai) - SaaS that turns any website into a consumable API for you to build on. Free 50 extractions and 10000 API calls / month.
  * [Scraper API](https://www.scraperapi.com/) — Cloud based web scraping API handles proxies, browsers, and CAPTCHAs. Scrape any web page with a simple API call. Get started with 1000 free API calls/month.
  * [ScrapingAnt](https://scrapingant.com/) — Headless Chrome scraping API and free checked proxies service. Javascript rendering, premium rotating proxies, CAPTCHAs avoiding. Free plans available.
  * [ScraperBox](https://scraperbox.com/) — Undetectable web scraping API using real Chrome browsers and proxy rotation. Use a simple API call to scrape any web page. Free plan has 1000 requests per month.
  * [ScrapingDog](https://scrapingdog.com/) — Scrapingdog handles millions of proxies, browsers and CAPTCHAs to provide you with HTML of any web page in a single API call. It also provides Web Scraper for Chrome & Firefox and a software for instant scraping demand. Free plans available.
  * [scrapinghub.com](https://scrapinghub.com) — Data scraping with visual interface and plugins. Free plan includes unlimited scraping on a shared server.
  * [ScrapingNinja](https://www.scrapingninja.co/) — Handle JS rendering, Chrome Headless, Proxy rotation and CAPTCHAs solving all in one place. The first 1000 are free of charge, no credit card required.
  * [Sheetson](https://sheetson.com) - Instantly turn any Google Sheets into RESTful API. Free plan available.
  * [shrtcode API](https://shrtco.de/docs) - Free URL Shortening API without authorisation and no request limits.
  * [Similar Words API](https://word-simi.herokuapp.com/) — An API to find similar words, has vocabulary of about 4Million words.
  * [Sofodata](https://www.sofodata.com/) - Create secure RESTful APIs from CSV files. Upload a CSV file and instantly access the data via its API allowing faster application development. Free plan includes 2 APIs and 2,500 API calls per month. No credit card required.
  * [tamber](https://tamber.com) — Put deep-learning powered recommendations in your app. Free 5k monthly active users.
  * [Time Door](https://timedoor.io) - A time series analysis API.
  * [TinyMCE](https://www.tiny.cloud) - rich text editing API. Core features free for unlimited usage.
  * [Unixtime](https://unixtime.co.za) - Free API to convert Unixtime to DateTime and vice versa.
  * [Vattly](https://vattly.com/) - Highly available, fast and secure VAT validation API, that provides full European Union coverage. 10 free API calls per day.
  * [Webhook.site](https://webhook.site) - Easily test HTTP webhooks with this handy tool that displays requests instantly.
  * [wit.ai](https://wit.ai/) — NLP for developers.
  * [wolfram.com](http://wolfram.com/language/) — Built-in knowledge-based algorithms in the cloud.
  * [wrapapi.com](https://wrapapi.com/) — Turn any website into a parameterized API. 30k API calls per month.
  * [Zenscrape](https://zenscrape.com/web-scraping-api) — Web scraping API with headless browsers, residentials IPs and simple pricing. 1000 free API calls/month, extra free credits for students and non-profits.
  * [ip-api](https://ip-api.com) — IP Geolocation API, Free for non-commercial use, no API key required, limited to 45 req/minute from the same IP address for the free plan.
  * [WebScraping.AI](https://webscraping.ai) - Simple Web Scraping API with built-in parsing, Chrome rendering and proxies. 5000 free API calls per month.
  * [Zipcodebase](https://zipcodebase.com) - Free Zip Code API, access to Worldwide Postal Code Data. 10000 free requests/month.
  * [EVA](http://eva.pingutil.com/) - Free email validator API, which helps to identify whether an email is disposable and having valid MX records.
  * [happi.dev](https://happi.dev) - Freemium api services collection (Music, Exchange Rate, Key value store, Language Detection, Password Generator, QRCode Generator, Lyrics). 8000 free API calls per month.

## Artifact Repos

 * [central.sonatype.org](https://central.sonatype.org) — The default artifact repository for Apache Maven, SBT and other build systems.
 * [cloudrepo.io](https://cloudrepo.io) - Cloud based, private and public, Maven and PyPi repositories. Free for open source projects.
 * [cloudsmith.io](https://cloudsmith.io) — Simple, secure and centralised repository service for Java/Maven, RedHat, Debian, Python, Ruby, Vagrant +more. Free tier + free for open source.
 * [jitpack.io](https://jitpack.io/) — Maven repository for JVM and Android projects on GitHub, free for public projects.
 * [packagecloud.io](https://packagecloud.io) — Easy to use repository hosting for: Maven, RPM, DEB, PyPi and RubyGem packages (has free tier).
 * [repsy.io](https://repsy.io) — 1 GB Free private/public Maven Repository.

## Tools for Teams and Collaboration

  * [3Cols](https://3cols.com/) - A free cloud based code snippet manager for personal and collaborative code.
  * [Bitwarden](https://bitwarden.com) — The easiest and safest way for individuals, teams, and business organizations to store, share, and sync sensitive data.
  * [Braid](https://www.braidchat.com/) — Chat app designed for teams. Free for public access group, unlimited users, history, and integrations. also it provide self-hostable open-source version.
  * [cally.com](https://cally.com/) — Find the perfect time and date for a meeting. Simple to use, works great for small and large groups.
  * [Discord](https://discordapp.com/) — Chat with public/private rooms. Markdown text, voice, video, and screen sharing capabilities. Free for unlimited users.
  * [evernote.com](https://evernote.com/) — Tool for organizing information. Share your notes and work together with others
  * [featurepeek.com](https://featurepeek.com) - Cloud provider-agnostic front-end feature environments with team collaboration tools built-in. Works with static and Dockerized front-ends. Free for public repositories.
  * [Fibery](https://fibery.io/) — Connected workspace platform. Free for single user, up to 2 GB disk space.
  * [Filestash](https://www.filestash.app) — A Dropbox-like file manager that connects to a range of protocols and platforms: S3, FTP, SFTP, Minio, Git, WebDAV, Backblaze, LDAP and more.
  * [flock.com](https://flock.com) — A faster way for your team to communicate. Free Unlimited Messages, Channels, Users, Apps & Integrations
  * [flowdock.com](https://www.flowdock.com/) — Chat and inbox, free for teams up to 5
  * [GitDuck](https://gitduck.com/) — Private live coding and remote pair programming for distributed teams. Open-source tool
  * [gitter.im](https://gitter.im/) — Chat, for GitHub. Unlimited public and private rooms, free for teams up to 25
  * [hangouts.google.com](https://hangouts.google.com/) — One place for all your conversations, for free, need a Google account
  * [helplightning.com](https://www.helplightning.com/) — Help over video with augmented reality. Free without analytics, encryption, support
  * [ideascale.com](https://ideascale.com/) — Allow clients to submit ideas and vote, free for 25 members in 1 community
  * [Igloo](https://www.igloosoftware.com/) — Internal portal for sharing documents, blogs and calendars etc. Free for up to 10 users.
  * [Keybase](https://keybase.io/) — Keybase is a cool FOSS alternative to Slack, it keeps everyone's chats and files safe, from families to communities to companies.
  * [Google Meet](https://meet.google.com/) — Use Google Meet for your business's online video meeting needs. Meet provides secure, easy-to-join online meetings.
  * [meet.jit.si](https://meet.jit.si/) — One click video conversations, screen sharing, for free
  * [Microsoft Teams](https://products.office.com/microsoft-teams/free) — Microsoft Teams is a chat-based digital hub that brings conversations, content, and apps together in one place all from a single experience. Free for up to 500k users.
  * [Miro](https://miro.com/) - Scalable, secure, cross-device and enterprise-ready team collaboration whiteboard for distributed teams. With freemium plan.
  * [Notion](https://www.notion.so/) - Notion is a note-taking and collaboration application with markdown support that also integrates tasks, wikis, and databases. The company describes the app as an all-in-one workspace for note-taking, project management and task management. In addition to cross-platform apps, it can be accessed via most web browsers.
  * [Nuclino](https://www.nuclino.com) - A lightweight and collaborative wiki for all your team's knowledge, docs, and notes. Free plan with all essential features, up to 50 items, 5GB total storage.
  * [Pendulums](https://pendulums.io/) - Pendulums is a free time tracking tool which helps you to manage your time in a better manner with an easy to use interface and useful statistics.
  * [Raindrop.io](https://raindrop.io) - Private and secure bookmarking app for macOS, Windows, Android, iOS and Web. Free Unlimited Bookmarks and Collaboration.
  * [element.io](https://element.io/) — A decentralized and open source communication tool built on Matrix. Group chats, direct messaging, encrypted file transfers, voice and video chats, and easy integration with other services.
  * [Rocket.Chat](https://rocket.chat/) - Shared inbox for teams, secure, unlimited and open source.
  * [seafile.com](https://www.seafile.com/) — Private or cloud storage, file sharing, sync, discussions. Private version is full. Cloud version has just 1 GB
  * [Slab](https://slab.com/) — A modern knowledge management service for teams. Free for up to 10 users.
  * [slack.com](https://slack.com/) — Free for unlimited users with some feature limitations
  * [Spectrum](https://spectrum.chat/) - Create public or private communities for free.
  * [StatusPile](https://www.statuspile.com/) - A status page of status pages. Track the status pages of your upstream providers.
  * [talky.io](https://talky.io/) — Free group video chat. Anonymous. Peer‑to‑peer. No plugins, signup, or payment required
  * [Tefter](https://tefter.io) - Bookmarking app with a powerful Slack integration. Free for open-source teams.
  * [TeleType](https://teletype.oorja.io/) — share terminals, voice, code, whiteboard and more. no sign-in required, end-to-end encrypted collaboration for developers.
  * [Tree Schema](https://treeschema.com/) — Data catalog and metadata management with APIs to manage data lineage as code. Free for teams of up to 5 users.
  * [twist.com](https://twist.com) — An asynchronous-friendly team communication app where conversations stay organized and on-topic. Free and Unlimited plans available. Discounts provided for eligible teams.
  * [typetalk.com](https://www.typetalk.com/) — Share and discuss ideas with your team through instant messaging on the web or on your mobile
  * [Tugboat](https://tugboat.qa) - Preview every pull request, automated and on-demand. Free for all, complimentary Nano tier for non-profits.
  * [whereby.com](https://whereby.com/) — One click video conversations, for free (formerly known as appear.in)
  * [userforge.com](https://userforge.com/) - Interconnected online personas, user stories and context mapping.  Helps keep design and dev in sync, free for up to 3 personas and 2 collaborators.
  * [wistia.com](https://wistia.com/) — Video hosting with viewer analytics, HD video delivery and marketing tools to help understand your visitors, 25 videos and Wistia branded player
  * [wormhol.org](https://www.wormhol.org/) — Straightforward file sharing service. Share unlimited files up to 5GB to as many peers as you want.
  * [zoom.us](https://zoom.us/) — Secure Video and Web conferencing, add-ons available. Free limited to 40 minutes
  * [shtab.app](https://shtab.app/) - Project management service that makes collaboration in the office and remotely transparent with tracker based on AI.
  * [zdoo.co](https://www.zdoo.co) — With CRM, OA, and Project management suites, zdoo is so powerful for team collaboration. Free cloud version with limited users and space offered, one-month free trial for premium versions.
  * [Zulip](https://zulip.com/) — Real-time chat with unique email-like threading model. Free plan includes 10,000 messages of search history and File storage up to 5 GB. also it provides self-hostable open-source version.
  * [Automate.io](https://automate.io) - Simple and complex automation workflow tool with over 200+ app integrations. 300 monthly actions and 5 bots are free
  * [robocorp.com](https://robocorp.com) - Open-source stack for powering Automation Ops. Try out Cloud features and implement simple automations for free. Robot work 240 min/month, 10 Assistant runs, Storage of 100 MB. 

## CMS

  * [acquia.com](https://www.acquia.com/) — Hosting for Drupal sites. Free tier for developers. Free development tools (such as Acquia Dev Desktop) also available
  * [Contentful](https://www.contentful.com/) — Headless CMS. Content management and delivery APIs in the cloud. Comes with one free Community space that includes 5 users, 25K records, 48 Content Types, 2 locales.
  * [Cosmic](https://www.cosmicjs.com/) — Headless CMS and API toolkit. Free personal plans for developers.
  * [Crystallize](https://crystallize.com) — Headless PIM with ecommerce support. Built-in GraphQL API. Free version includes unlimited users, 1000 catalogue items, 5 GB/month bandwidth and 25k/month API calls.
  * [Forestry.io/](https://forestry.io/) — Headless CMS. Give your editors the power of Git. Create and edit Markdown-based content with ease. Comes with three free sites that includes 3 editors, Instant Previews. Integrates with blogs hosted on Netlify/GitHubpages/ elsewhere
  * [kontent.ai](https://www.kontent.ai) - A Content-as-a-Service platform that gives you all the headless CMS benefits while empowering marketers at the same time. Developer plan provides 2 users with unlimited projects with 2 environments for each, 500 content items, 2 languages with Delivery and Management API, and Custom elements support. Larger plans available to meet your needs.
  * [Prismic](https://www.prismic.io/) — Headless CMS. Content management interface with fully hosted and scalable API. The Community Plan provides 1 user with unlimited API calls, documents, custom types, assets, and locales. Everything that you need for your next project. Bigger free plans available for Open Content/Open Source projects.
  * [sanity.io](https://www.sanity.io/) – Hosted backend for structured content with customizable MIT licensed editor built with React. Unlimited projects. 3 users, 2 datasets, 500k API CDN requests, 5GB assets for free per project
  * [sensenet](https://sensenet.com) - API-first headless CMS providing enterprise-grade solutions for businesses of all size. The Developer plan provides 3 users, 500 content items, 3 built-in roles, 25+5 content types, fully accessible REST API, document preview generation and Office Online editing.
  * [GraphCMS](https://graphcms.com/) - Offers free tier for small projects. GraphQL first API. Move away from legacy solutions to the GraphQL native Headless CMS - and deliver omnichannel content API first.


## Code Quality

  * [beanstalkapp.com](https://beanstalkapp.com/) — A complete workflow to write, review and deploy code), free account for 1 user and 1 repository with 100 MB of storage
  * [browserling.com](https://www.browserling.com/) — Live interactive cross-browser testing, free only 3 minutes sessions with MS IE 9 under Vista at 1024 x 768 resolution
  * [codacy.com](https://www.codacy.com/) — Automated code reviews for PHP, Python, Ruby, Java, JavaScript, Scala, CSS and CoffeeScript, free for unlimited public and private repositories
  * [Codeac.io](https://www.codeac.io/infrastructure-as-code.html?ref=free-for-dev) - Automated Infrastructure as Code review tool for DevOps integrates with GitHub, Bitbucket and GitLab (even self-hosted). In addition to standard languages, it analyzes also Ansible, Terraform, CloudFormation, Kubernetes, and more. (open-source free)
  * [CodeBeat](https://codebeat.co) — Automated Code Review Platform available for many languages. Free forever for public repositories with Slack & E-mail integration.
  * [codeclimate.com](https://codeclimate.com/) — Automated code review, free for Open Source and unlimited organisation-owned private repos (up to 4 collaborators). Also free for students and institutions.
  * [codecov.io](https://codecov.io/) — Code coverage tool (SaaS), free for Open Source and 1 free private repo
  * [CodeFactor](https://www.codefactor.io) — Automated Code Review for Git. Free version includes unlimited users, unlimited public repositories and 1 private repo.
  * [codescene.io](https://codescene.io/) - CodeScene prioritizes technical debt based on how the developers work with the code and visualizes organizational factors like team coupling and system mastery. Free for Open Source.
  * [coveralls.io](https://coveralls.io/) — Display test coverage reports, free for Open Source
  * [dareboost](https://dareboost.com) - 5 free analysis report for web performance, accessibility, security each month
  * [deepcode.ai](https://www.deepcode.ai) — DeepCode finds bugs, security vulnerabilities, performance and API issues based on AI. DeepCode's speed of analysis allow us to analyse your code in real time and deliver results when you hit the save button in your IDE. Supported languages are Java, C/C++, JavaScript, Python, and TypeScript. Integrations with GitHub, BitBucket and Gitlab. Free for open source and private repos, free up to 30 developers.
  * [deepscan.io](https://deepscan.io) — Advanced static analysis for automatically finding runtime errors in JavaScript code, free for Open Source
  * [DeepSource](https://deepsource.io/) - DeepSource continuously analyzes source code changes, finds and fixes issues categorized under security, performance, anti-patterns, bug-risks, documentation and style. Native integration with GitHub, GitLab and Bitbucket.
  * [eversql.com](https://www.eversql.com/) — EverSQL - The #1 platform for database optimization. Gain critical insights into your database and SQL queries, auto-magically.
  * [gerrithub.io](https://review.gerrithub.io/) — Gerrit code review for GitHub repositories for free
  * [gocover.io](https://gocover.io/) — Code coverage for any [Go](https://golang.org/) package
  * [goreportcard.com](https://goreportcard.com/) — Code Quality for Go projects, free for Open Source
  * [gtmetrix.com](https://gtmetrix.com/) — Reports and thorough recommendations to optimize websites
  * [holistic.dev](https://holistic.dev/) - The #1 static code analyzer for Postgresql optimization. Performance, security, and architect database issues automatic detection service
  * [houndci.com](https://houndci.com/) — Comments on GitHub commits about code quality, free for Open Source
  * [Imgbot](https://github.com/marketplace/imgbot) — Imgbot is a friendly robot that optimizes your images and saves you time. Optimized images mean smaller file sizes without sacrificing quality. It's free for open source.
  * [Kritika](https://kritika.io/) — Static Code Analysis for Perl with integration for GitHub. Free for unlimited public repositories.
  * [resmush.it](https://resmush.it) — reSmush.it is a FREE API that provides image optimization. reSmush.it has been implemented on the most common CMS such as Wordpress, Drupal or Magento. reSmush.it is the most used image optimization API with more than 7 billions images already treated, and is still Free of charge.
  * [insight.sensiolabs.com](https://insight.sensiolabs.com/) — Code Quality for PHP/Symfony projects, free for Open Source
  * [lgtm.com](https://lgtm.com) — Continuous security analysis for Java, Python, JavaScript, TypeScript, C#, C and C++, free for Open Source
  * [reviewable.io](https://reviewable.io/) — Code review for GitHub repositories, free for public or personal repos
  * [parsers.dev](https://parsers.dev/) - Abstract syntax tree parsers and intermediate representation compilers as a service
  * [scan.coverity.com](https://scan.coverity.com/) — Static code analysis for Java, C/C++, C# and JavaScript, free for Open Source
  * [scrutinizer-ci.com](https://scrutinizer-ci.com/) — Continuous inspection platform, free for Open Source
  * [shields.io](https://shields.io) — Quality metadata badges for open source projects
  * [Sider](https://sider.review) — Code review platform for many languages. Supports integration with GitHub. Free for public repositories with unlimited users.
  * [sonarcloud.io](https://sonarcloud.io) — Automated source code analysis for Java, JavaScript, C/C++, C#, VB.NET, PHP, Objective-C, Swift, Python, Groovy and even more languages, free for Open Source
  * [SourceLevel](https://sourcelevel.io/) — Automated Code Review and Team Analytics. Free for Open Source and organizations up to 5 collaborators.
  * [Typo CI](https://github.com/marketplace/typo-ci) — Typo CI reviews your Pull Requests and commits for spelling mistakes, free for Open Source.
  * [webceo.com](https://www.webceo.com/) — SEO tools but with also code verifications and different type of advices
  * [zoompf.com](https://zoompf.com/) — Fix the performance of your web sites, detailed analysis

## Code Search and Browsing

  * [codota.com](https://www.codota.com/) — Codota helps developers create better software, faster by providing insights learned from all the code in the world. Plugin available.
  * [libraries.io](https://libraries.io/) — Search and dependency update notifications for 32 different package managers, free for open source
  * [Namae](https://namae.dev/) - Search across various websites like github,gitlab,heroku,netlify and many more for availabilty of your project name.
  * [searchcode.com](https://searchcode.com/) — Comprehensive text-based code search, free for Open Source
  * [sourcegraph.com](https://about.sourcegraph.com/) — Java, Go, Python, Node.js, etc., code search/cross-references, free for Open Source
  * [tickgit.com](https://www.tickgit.com/) — Surfaces `TODO` comments (and other markers) to identify areas of code worth returning to for improvement.
  * [CodeKeep](https://codekeep.io) - Google Keep for Code Snippets. Organize,Discover and share code snippets, featuring a powerful code screenshot tool with preset templates and linking feature.

## CI and CD

  * [AccessLint](https://github.com/marketplace/accesslint) — AccessLint brings automated web accessibility testing into your development workflow. It's free for open source and education purposes.
  * [appcircle.io](https://appcircle.io) — Automated mobile CI/CD/CT for iOS and Android with online device emulators. 20 minutes build timeout (60 mins for Open Source) with single concurrency for free.
  * [appveyor.com](https://www.appveyor.com/) — CD service for Windows, free for Open Source
  * [bitrise.io](https://www.bitrise.io/) — A CI/CD for mobile apps, native or hybrid. With 200 free builds/month 10 min build time and two team members. OSS projects get 45 min build time, +1 concurrency and unlimited team size.
  * [buddy.works](https://buddy.works/) — A CI/CD with 5 free projects and 1 concurrent runs (120 executions/month)
  * [buddybuild.com](https://www.buddybuild.com/) — Build, deploy and gather feedback for your iOS and Android apps in one seamless, iterative system
  * [circleci.com](https://circleci.com/) — Free for one concurrent build
  * [cirrus-ci.org](https://cirrus-ci.org) - Free for public GitHub repositories
  * [codefresh.io](https://codefresh.io) — Free-for-Life plan: 1 build, 1 environment, shared servers, unlimited public repos
  * [codemagic.io](https://codemagic.io/) - Free 500 build minutes/month
  * [codeship.com](https://codeship.com/) — 100 private builds/month, 5 private projects, unlimited for Open Source
  * [Continuous PHP](https://continuousphp.com/) — continuousphp is the first and only PHP-centric Platform to build, package, test and deploy applications in the same workflow. Free for Community Projects i.e. OSS/Public/Educational projects.
  * [deployhq.com](https://www.deployhq.com/) — 1 project with 10 daily deployments (30 build minutes/month)
  * [drone](https://cloud.drone.io/) - Drone Cloud enables developers to run Continuous Delivery pipelines across multiple architectures - including x86 and Arm (both 32 bit and 64 bit) - all in one place
  * [LayerCI](https://layerci.com) — CI for full stack projects. 1 full stack preview environment with 5GB memory & 3 CPUs .
  * [ligurio/awesome-ci](https://github.com/ligurio/awesome-ci) — Comparison of Continuous Integration services
  * [Octopus Deploy](https://octopus.com) - Automated deployment and release-management. Free for <= 10 deployment targets.
  * [scalr.com](https://scalr.com/) - Remote state & operations backend for Terraform with full CLI support, integration with OPA and a hierarchical configuration model. Free up to 5 users.
  * [semaphoreci.com](https://semaphoreci.com/) — Free for Open Source, 100 private builds per month
  * [shippable.com](https://app.shippable.com/) — 150 private builds/month, free for 1 build container, private and public repos
  * [Squash Labs](https://www.squash.io/) — creates a VM for each branch and makes your app available from a unique URL, Unlimited public & private repos, Up to 2 GB VM Sizes.
  * [stackahoy.io](https://stackahoy.io) — 100% free. Unlimited deployments, branches and builds
  * [styleci.io](https://styleci.io/) — Public GitHub repositories only
  * [travis-ci.org](https://travis-ci.org/) — Free for public GitHub repositories
  * [Mergify](https://mergify.io) — workflow automation and merge queue for GitHub — Free for public GitHub repositories

## Testing

  * [Applitools.com](https://applitools.com/) — Smart visual validation for web, native mobile and desktop apps. Integrates with almost all automation solutions (like Selenium and Karma) and remote runners (Sauce Labs, Browser Stack). free for open source. A free tier for a single user with limited checkpoints per week.
  * [Appetize](https://appetize.io) — Test your Android & iOS apps on this Cloud Based Android Phone/Tablets emulators and iPhone/iPad simulators directly in your browser. Free tier includes 1 concurrent session with 100 minutes usage per month. No limit on app size.
  * [Bird Eats Bug](https://www.birdeatsbug.com/) — Report bugs faster (and better). Record your screen with Bird browser extension, it will auto-capture technical data that engineers need to debug. Free tier suitable for small teams.
  * [browserstack.com](https://www.browserstack.com/) — Manual and automated browser testing, [free for Open Source](https://www.browserstack.com/open-source?ref=pricing)
  * [checkbot.io](https://www.checkbot.io/) — Browser extension that tests if your website follows 50+ SEO, speed and security best practices. Free tier for smaller websites.
  * [crossbrowsertesting.com](https://crossbrowsertesting.com) - Manual, Visual, and Selenium Browser Testing in the cloud - [free for Open Source](https://crossbrowsertesting.com/open-source)
  * [cypress.io](https://www.cypress.io/) - Fast, easy and reliable testing for anything that runs in a browser. Cypress Test Runner is always free and open source with no restrictions and limitations. Cypress Dashboard is free for open source projects for up to 5 users.
  * [everystep-automation.com](https://www.everystep-automation.com/) — Records and replays all steps made in a web browser and creates scripts,... free with fewer options
  * [Gremlin](https://www.gremlin.com/gremlin-free-software) — Gremlin's Chaos Engineering tools allow you to safely, securely, and simply inject failure into your systems to find weaknesses before they cause customer-facing issues. Gremlin Free provides access to Shutdown and CPU attacks on up to 5 hosts or containers.
  * [gridlastic.com](https://www.gridlastic.com/) — Selenium Grid testing with free plan up to 4 simultaneous selenium nodes/10 grid starts/4,000 test minutes/month
  * [loadmill.com](https://www.loadmill.com/) - Automatically create API and load tests by analyzing network traffic. Simulate up to 50 concurrent users for up to 60 minutes for free every month.
  * [percy.io](https://percy.io) - Add visual testing to any web app, static site, style guide, or component library.  Unlimited team members, Demo app and unlimited projects, 5,000 snapshots / month.
  * [reflect.run](https://reflect.run) - Codeless automated tests for web apps. Tests can be scheduled in-app or executed from a CI/CD tool. Each test run includes a full video recording along with console and network logs. The free tier includes an unlimited number of saved tests, with 25 test runs per month and up to 3 users.
  * [saucelabs.com](https://saucelabs.com/) — Cross browser testing, Selenium testing and mobile testing, [free for Open Source](https://saucelabs.com/open-source)
  * [testingbot.com](https://testingbot.com/) — Selenium Browser and Device Testing, [free for Open Source](https://testingbot.com/open-source)
  * [tesults.com](https://www.tesults.com) — Test results reporting and test case management. Integrates with popular test frameworks. Open Source software developers, individuals, educators, and small teams getting started can request discounted and free offerings beyond basic free project.
  * [websitepulse.com](https://www.websitepulse.com/tools/) — Various free network and server tools.
  * [qase.io](https://qase.io) - Test management system for Dev and QA teams. Manage test cases, compose test runs, perform test runs, track defects and measure impact. The free tier includes all core features, with 500Mb available for attachments and up to 3 users.
  * [knapsackpro.com](https://knapsackpro.com) - Speed up your tests with optimal test suite parallelisation on any CI provider. Split Ruby, JavaScript tests on parallel CI nodes to save time. Free plan for up to 10 minutes test files and free unlimited plan for Open Source projects.
  * [webhook.site](https://webhook.site) - Verify webhooks, outbound HTTP requests, or emails with a custom URL.  Temporary URL and email address is always free.
  * [Vaadin](https://vaadin.com) — Build scalable UIs in Java or TypeScript, and use the integrated tooling, components and design system to iterate faster, design better and simplify the development process. Unlimited Projects with 5 years free maintenance.

## Security and PKI

  * [alienvault.com](https://www.alienvault.com/open-threat-exchange/reputation-monitor) — Uncovers compromised systems in your network
  * [atomist.com](https://atomist.com/) — A quicker and more convenient way to automate a variety of development tasks. Now in beta.
  * [auth0.com](https://auth0.com/) — Hosted free for development SSO. Up to 2 social identity providers for closed-source projects.
  * [Authress](https://authress.io/) — Authentication login and access control, unlimited identity providers for any project. Facebook, Google, Twitter and more. First 1000 API calls are free.
  * [Authy](https://authy.com) - Two-factor authentication (2FA) on multiple devices, with backups. Drop-in replacement for Google Authenticator. Free for up to 100 successful authentications.
  * [bitninja.io](https://bitninja.io/) — Botnet protection through a blacklist, free plan only reports limited information on each attack
  * [cloudsploit.com](https://cloudsploit.com/) — Amazon Web Services (AWS) security and compliance auditing and monitoring
  * [Cmd](https://cmd.com/) — Security platform providing real-time access control and dynamic policy enforcement on every Linux instance in your cloud or datacenter
  * [CodeNotary.io](https://www.codenotary.io/) — Open Source platform with indelible proof to notarize code, files, directories or container
  * [crypteron.com](https://www.crypteron.com/) — Cloud-first, developer-friendly security platform prevents data breaches in .NET and Java applications
  * [Dependabot](https://dependabot.com/) Automated dependency updates for Ruby, JavaScript, Python, PHP, Elixir, Rust, Java (Maven and Gradle), .NET, Go, Elm, Docker, Terraform, Git Submodules and GitHub Actions.
  * [DJ Checkup](https://djcheckup.com) — Scan your Django site for security flaws with this free, automated, checkup tool. Forked from the Pony Checkup site.
  * [Doppler](https://doppler.com/) — Universal Secrets Manager for application secrets and config, with support for syncing to various cloud providers. Free for unlimited users with basic access controls.
  * [duo.com](https://duo.com/) — Two-factor authentication (2FA) for website or app. Free for 10 users, all authentication methods, unlimited, integrations, hardware tokens
  * [Firebase Auth](https://firebase.google.com/products/auth/) — Free end-to-end identity solution, email and password accounts, Google, Twitter, Facebook, GitHub login, phone auth (up to 10k/month), and more.
  * [foxpass.com](https://www.foxpass.com/) — Hosted LDAP and RADIUS. Easy per-user logins to servers, VPNs and wireless networks. Free for 10 users
  * [globalsign.com](https://www.globalsign.com/en/ssl/ssl-open-source/) — Free SSL certificates for Open Source
  * [Have I been pwned?](https://haveibeenpwned.com) — REST API for fetching the information on the breaches.
  * [Internet.nl](https://internet.nl) — Test for modern Internet Standards like IPv6, DNSSEC, HTTPS, DMARC, STARTTLS and DANE
  * [Jumpcloud](https://jumpcloud.com/) — Provides directory as a service similar to Azure AD, user management, single sign-on, and RADIUS authentication. Free for up to 10 users.
  * [keychest.net](https://keychest.net) - SSL expiry management and cert purchase with an integrated CT database
  * [letsencrypt.org](https://letsencrypt.org/) — Free SSL Certificate Authority with certs trusted by all major browsers
  * [LoginRadius](https://www.loginradius.com/) — Managed User Authentication service for free. Email registration and 3 social providers.
  * [logintc.com](https://www.logintc.com/) — Two-factor authentication (2FA) by push notifications, free for 10 users, VPN, Websites and SSH
  * [meterian.io](https://www.meterian.io/) - Monitor Java, Javascript, .NET, Scala, Ruby and NodeJS projects for security vulnerabilities in dependencies. Free for one private project, unlimited projects for open source.
  * [Mozilla Observatory](https://observatory.mozilla.org/) — Find and fix security vulnerabilities in your site.
  * [Okta](https://developer.okta.com/) — User management, authentication and authorization. Free for up to 1000 monthly active users.
  * [onelogin.com](https://www.onelogin.com/) — Identity as a Service (IDaaS), Single Sign-On Identity Provider, Cloud SSO IdP, 3 company apps and 5 personal apps, unlimited users
  * [opswat.com](https://www.opswat.com/) — Security Monitoring of computers, devices, applications, configurations,... Free 25 users and 30 days history users.
  * [pyup.io](https://pyup.io) — Monitor Python dependencies for security vulnerabilities and update them automatically. Free for one private project, unlimited projects for open source.
  * [qualys.com](https://www.qualys.com/community-edition) — Find web app vulnerabilities, audit for OWASP Risks
  * [report-uri.io](https://report-uri.io/) — CSP and HPKP violation reporting
  * [ringcaptcha.com](https://ringcaptcha.com/) — Tools to use phone number as id, available for free
  * [snyk.io](https://snyk.io) — Can find and fix known security vulnerabilities in your open source dependencies. Unlimited tests and remediation for open source projects. Limited to 200 tests/month for your private projects.
  * [Sqreen](https://www.sqreen.com/) — Application security monitoring and protection (RASP, WAF and more) for web applications and APIs. Free for 1 app and 3 million requests.
  * [ssllabs.com](https://www.ssllabs.com/ssltest/) — Very deep analysis of the configuration of any SSL web server
  * [StackHawk](https://www.stackhawk.com/) Automate application scanning throughout your pipeline to find and fix security bugs before they hit production. Unlimited scans and environments for a single app.
  * [Sucuri SiteCheck](https://sitecheck.sucuri.net) - Free website security check and malware scanner
  * [Protectumus](https://protectumus.com) - Free website security check, site antivirus and server firewall (WAF) for PHP. Email notifications for registered users in free tier.
  * [TestTLS.com](https://testtls.com) - Test a SSL/TLS service for secure server configuration, certificates, chains etc. Not limited to HTTPS.
  * [threatconnect.com](https://threatconnect.com) — Threat intelligence: It is designed for individual researchers, analysts and organizations who are starting to learn about cyber threat intelligence. Free up to 3 Users
  * [tinfoilsecurity.com](https://www.tinfoilsecurity.com/) — Automated vulnerability scanning. Free plan allows weekly XSS scans
  * [Ubiq Security](https://ubiqsecurity.com/) — Encrypt and decrypt data with 3 lines of code and automatic key management. Free for 1 application and up to 1,000,000 encryptions per month.
  * [Virgil Security](https://virgilsecurity.com/) — Tools and services for implementing end-to-end encryption, database protection, IoT security and more in your digital solution. Free for applications with up to 250 users.
  * [Virushee](https://virushee.com/) — Privacy-oriented file/data scanning powered by hybrid heuristic and AI-assisted engine. Possible to use internal dynamic sandbox analysis. Limited to 50MB per file upload

## Management System

  * [bitnami.com](https://bitnami.com/) — Deploy prepared apps on IaaS. Management of 1 AWS micro instance free
  * [Esper](https://esper.io) — MDM and MAM for Android Devices with DevOps. 100 devices free with 1 user license and 25 MB Application Storage.
  * [jamf.com](https://www.jamf.com/) —  Device management for iPads, iPhones and Macs, 3 devices free
  * [Miradore](https://miradore.com) — Device Management service. Stay up-to-date with your device fleet and secure an unlimited number of devices for free. Free plan offers basic features.
  * [moss.sh](https://moss.sh) - Help developers deploy and manage their web apps and servers. Free up to 25 git deployments per month
  * [runcloud.io](https://runcloud.io/) - Server management focusing mainly on PHP projects. Free for up to 1 server.
  * [ploi.io](https://ploi.io/) - Server management tool to easily manage and deploy your servers & sites. Free for 1 server.

## Messaging

  * [Ably](https://www.ably.com/) - Realtime messaging service with presence, persistence and guaranteed delivery. Free plan includes 3m messages per month, 100 peak connections and 100 peak channels.
  * [cloudamqp.com](https://www.cloudamqp.com/) — RabbitMQ as a Service. Little Lemur plan: max 1 million messages/month, max 20 concurrent connections, max 100 queues, max 10,000 queued messages, multiple nodes in different AZ's
  * [connectycube.com](https://connectycube.com) - Unlimited chat messages, p2p voice & video calls, files attachments and push notifications. Free for apps up to 20K MAU.
  * [courier.com](https://www.courier.com/) — Single API for push, in-app, email, chat, SMS, and other messaging channels with template management and other features. Free plan includes 10,000 messages/mo.
  * [pusher.com](https://pusher.com/) — Realtime messaging service. Free for up to 100 simultaneous connections and 200,000 messages/day
  * [scaledrone.com](https://www.scaledrone.com/) — Realtime messaging service. Free for up to 20 simultaneous connections and 100,000 events/day
  * [synadia.com](https://synadia.com/ngs) — [NATS.io](https://nats.io) as a service. Global, AWS, GCP, and Azure. Free forever with 4k msg size, 50 active connections and 5GB of data per month.
  * [cloudkarafka.com](https://www.cloudkarafka.com/) - Free Shared Kafka cluster, up to 5 topics, 10MB data per topic and 28 days of data retention.
  * [pubnub.com](https://www.pubnub.com/) - Swift, Kotlin and React messaging at 1 million transactions each month. Transactions may contain multiple messages.


## Log Management

  * [bugfender.com](https://bugfender.com/) — Free up to 100k log lines/day with 24 hours retention
  * [humio.com](https://www.humio.com/) — Free up to 2 GB/day with 7 days retention
  * [logdna.com](https://logdna.com) - Free for a single user, no retention, unlimited hosts and sources
  * [logentries.com](https://logentries.com/) — Free up to 5 GB/month with 7 days retention
  * [loggly.com](https://www.loggly.com/) — Free for a single user, see the lite option
  * [logz.io](https://logz.io/) — Free up to 3 GB/day, 3 days retention
  * [ManageEngine Log360 Cloud](https://www.manageengine.com/cloud-log-management) — Log Management service powered by Manage Engine. Free Plan offers 50 GB storage with 1 Month retention.
  * [papertrailapp.com](https://papertrailapp.com/) — 48 hours search, 7 days archive, 100 MB/month
  * [sematext.com](https://sematext.com/logsene) — Free up to 500 MB/day, 7 days retention
  * [sumologic.com](https://www.sumologic.com/) — Free up to 500 MB/day, 7 days retention

## Translation Management

  * [crowdin.com](https://crowdin.com/) — Unlimited projects, unlimited strings and collaborators for Open Source
  * [lingohub.com](https://lingohub.com/) — Free up to 3 users, always free for Open Source
  * [localazy.com](https://localazy.com) - Free for 1000 source language strings, unlimited languages, unlimited contributors, startup and open source deals
  * [localizely.com](https://localizely.com/) — Free for Open Source
  * [Loco](https://localise.biz/) — Free up to 2000 translations, Unlimited translators, 10 languages/project, 1000 translatable assets/project
  * [oneskyapp.com](https://www.oneskyapp.com/) — Limited free edition for up to 5 users, free for Open Source
  * [POEditor](https://poeditor.com/) — Free up to 1000 strings
  * [SimpleLocalize](https://simplelocalize.io/) - Free up to 100 translation keys, unlimited strings, unlimited languages, startup deals
  * [transifex.com](https://www.transifex.com/) — Free for Open Source
  * [Translation.io](https://translation.io) - Free for Open Source
  * [webtranslateit.com](https://webtranslateit.com/) — Free up to 500 strings
  * [weblate.org](https://weblate.org/) — It's free for libre projects up to 10,000 string source for the free tier, and Unlimited Self-hosted on-premises.

## Monitoring

  * [Pingmeter.com](https://pingmeter.com/) - 5 uptime monitors with 10 minutes interval. monitor SSH, HTTP, HTTPS, and any custom TCP ports.
  * [amixr.io](https://amixr.io/) - Developer-friendly alerting and on-call management with brilliant Slack Integration, API and Terraform. Free phone call, SMS, Telegram, Slack and E-Mail packages.
  * [appdynamics.com](https://www.appdynamics.com/) — Free for 24 hours metrics, application performance management agents limited to one Java, one .NET, one PHP and one Node.js
  * [appneta.com](https://www.appneta.com/) — Free with 1-hour data retention
  * [assertible.com](https://assertible.com) — Automated API testing and monitoring. Free plans for teams and individuals.
  * [bearer.sh](https://www.bearer.sh) - Automatically Monitor API Requests, Track Performance, Detect Anomalies and Fix Issues on your critical API Usage. Install the Bearer Agent for Free with 1 line of code.
  * [blackfire.io](https://blackfire.io/) — Blackfire is the SaaS-delivered Application Performance Solution. Free Hacker plan (PHP only)
  * [checklyhq.com](https://checklyhq.com) - Open source E2E / Synthetic monitoring and deep API monitoring for developers. Free plan with 5 users and 50k+ check runs.
  * [circonus.com](https://www.circonus.com/) — Free for 20 metrics
  * [cloudsploit.com](https://cloudsploit.com) — AWS security and configuration monitoring. Free: unlimited on-demand scans, unlimited users, unlimited stored accounts. Subscription: automated scanning, API access, etc.
  * [datadoghq.com](https://www.datadoghq.com/) — Free for up to 5 nodes
  * [deadmanssnitch.com](https://deadmanssnitch.com/) — Monitoring for cron jobs. 1 free snitch (monitor), more if you refer others to sign up
  * [elastic.co](https://www.elastic.co/solutions/apm) — Instant performance insights for JS developers. Free with 24 hours data retention
  * [freeboard.io](https://freeboard.io/) — Free for public projects. Dashboards for your Internet of Things (IoT) projects
  * [freshworks.com](https://www.freshworks.com/website-monitoring/) — Monitor 50 URLs at 1-minute interval with 10 Global locations and 5 Public status pages for Free
  * [gitential.com](https://gitential.com) — Software Development Analytics platform. Free: unlimited public repositories, unlimited users, free trial for private repos. On-prem version available for enterprise.
  * [Grafana Cloud](https://grafana.com/products/cloud/) - Grafana Cloud is a composable observability platform, integrating metrics and logs with Grafana. Free: 3 users, 10 dashboards, 100 alerts, metrics storage in Prometheus and Graphite (10,000 series, 14 days retention), logs storage in Loki (50 GB of logs, 14 days retention)
  * [healthchecks.io](https://healthchecks.io) — Monitor your cron jobs and background tasks. Free for up to 20 checks.
  * [inspector.dev](https://www.inspector.dev) - A complete Real-Time monitoring dashboard in less than one minute with free forever tier.
  * [instrumentalapp.com](https://instrumentalapp.com) - Beautiful and easy-to-use application and server monitoring with up to 500 metrics and 3 hours of data visibility for free
  * [keychest.net/speedtest](https://keychest.net/speedtest) - Independent speed test and TLS handshake latency test against Digital Ocean
  * [letsmonitor.org](https://letsmonitor.org) - SSL monitoring, free for up to 5 monitors
  * [loader.io](https://loader.io/) — Free load testing tools with limitations
  * [newrelic.com](https://www.newrelic.com) — New Relic observability platform built to help engineers create more perfect software. From monoliths to serverless, you can instrument everything, then analyze, troubleshoot, and optimize your entire software stack. Free tier offers 100GB/month of free data ingest, 1 free full access user, and unlimited free basic users.
  * [nixstats.com](https://nixstats.com) - Free for one server. E-Mail Notifications, public status page, 60 second interval and more.
  * [nodequery.com](https://nodequery.com/) — Free basic server monitors up to 10 servers
  * [opsgenie.com](https://www.opsgenie.com/) — Powerful alerting and on-call management for operating always-on services. Free up to 5 users.
  * [paessler.com](https://www.paessler.com/) — Powerful infrastructure and network monitoring solution including alerting, strong visualization capabilities and basic reporting. Free up to 100 sensors.
  * [pagertree.com](https://pagertree.com/) - Simple interface for alerting and on-call management. Free up to 5 users.
  * [pingbreak.com](https://pingbreak.com/) — Modern uptime monitoring service. Check unlimited URLs and get downtime notifications via Discord, Slack or email.
  * [sematext.com](https://sematext.com/) — Free for 24 hours metrics, unlimited number of servers, 10 custom metrics, 500,000 custom metrics data points, unlimited dashboards, users, etc.
  * [sitemonki.com](https://sitemonki.com/) — Website, domain, Cron & SSL monitoring, 5 monitors in each category for free
  * [skylight.io](https://www.skylight.io/) — Free for first 100,000 requests (Rails only)
  * [speedchecker.xyz](https://probeapi.speedchecker.xyz/) — Performance Monitoring API, checks Ping, DNS, etc.
  * [stathat.com](https://www.stathat.com/) — Get started with 10 stats for free, no expiration
  * [statuscake.com](https://www.statuscake.com/) — Website monitoring, unlimited tests free with limitations
  * [statusgator.com](https://statusgator.com/) — Status page monitoring, 3 monitors free
  * [thousandeyes.com](https://www.thousandeyes.com/) — Network and user experience monitoring. 3 locations and 20 data feeds of major web services free
  * [thundra.io/apm](https://www.thundra.io/apm) — Application monitoring and debugging. Has a free tier up to 250k monthly invocations.
  * [uptimerobot.com](https://uptimerobot.com/) — Website monitoring, 50 monitors free
  * [uptimetoolbox.com](https://uptimetoolbox.com/) — Free monitoring for 5 websites, 60 second intervals, public statuspage.
  * [zenduty.com](https://www.zenduty.com/) — End-to-end incident management, alerting, on-call management and response orchestration platform for network operations, site reliability engineering and DevOps teams. Free for upto 5 users.

## Crash and Exception Handling

  * [CatchJS.com](https://catchjs.com/) - JavaScript error tracking with screenshots and click trails. Free for open source projects.
  * [bugsnag.com](https://www.bugsnag.com/) — Free for up to 2,000 errors/month after the initial trial
  * [exceptionless](https://exceptionless.com) — Real-time error, feature, log reporting and more. Free for 3k events per month/1 user. Open source and easy to self-host for unlimited use.
  * [GlitchTip](https://glitchtip.com/) — Simple, open source error tracking. Compatible with open-source Sentry SDKs. 1000 events per month for free, or can self-host with no limits
  * [honeybadger.io](https://www.honeybadger.io) - Exception, uptime, and cron monitoring. Free for small teams and open-source projects (12,000 errors/month).
  * [rollbar.com](https://rollbar.com/) — Exception and error monitoring, free plan with 5,000 errors/month, unlimited users, 30 days retention
  * [sentry.io](https://sentry.io/) — Sentry tracks app exceptions in real-time, has a small free plan. Free for 5k errors per month/ 1 user, unrestricted use if self-hosted

## Search

  * [algolia.com](https://www.algolia.com/) — Hosted search-as-you-type (instant). Free hacker plan up to 10,000 documents and 100,000 operations. Bigger free plans available for community/Open Source projects
  * [bonsai.io](https://bonsai.io/) — Free 1 GB memory and 1 GB storage
  * [searchly.com](http://www.searchly.com/) — Free 2 indices and 20 MB storage
  * [pagedart.com](https://pagedart.com/) - AI search as a service the free tier includes 1000 Documents, 50000 searches. Larger free tiers are possible for worthwhile projects.

## Email

  * [10minutemail](https://10minutemail.com) - Free, temporary email for testing.
  * [AnonAddy](https://anonaddy.com) - Open-source anonymous email forwarding, create unlimited email aliases for free
  * [biz.mail.ru](https://biz.mail.ru/) — 5,000 mailboxes with 25 GB each per custom domain with DNS hosting
  * [Bump](https://bump.email/) - Free 10 Bump email addresses, 1 custom domain
  * [Burnermail](https://burnermail.io/) – Free 5 Burner Email Addresses, 1 Mailbox, 7 day Mailbox History
  * [Buttondown](https://buttondown.email/) — Newsletter service. Up to 1,000 subscribers free
  * [CloudMailin](https://www.cloudmailin.com/) - Incoming email via HTTP POST and transactional outbound - 10,000 free emails/month
  * [cloudmersive.com](https://www.cloudmersive.com/email-verification-api) — Email validation and verification API for developers, 2,000 free API requests/month
  * [Contact.do](https://contact.do/) — Contact form in a link (bitly for contact forms) - totally free!
  * [debugmail.io](https://debugmail.io/) — Easy to use testing mail server for developers
  * [elasticemail.com](https://elasticemail.com) — 100 free emails/day. 1,000 emails for $0.09 through API (pay as you go).
  * [forwardemail.net](https://forwardemail.net) — Free email forwarding for custom domains. Create and forward an unlimited amount of email addresses with your domain name (**note**: You must pay if you use .casa, .cf, .click, .email, .fit, .ga, .gdn, .gq, .loan, .london, .men, .ml, .pl, .rest, .ru, .tk, .top, .work TLDs due to spam)
  * [ImprovMX](https://improvmx.com) – Free email forwarding
  * [inumbo.com](http://inumbo.com/) — SMTP based spam filter, free for 10 users
  * [kickbox.io](https://kickbox.io/) — Verify 100 emails free, real-time API available
  * [mailazy.com](https://mailazy.com/) — 250 emails/day free
  * [mail-tester.com](https://www.mail-tester.com) — Test if email's dns/spf/dkim/dmarc settings are correct, 20 free/month
  * [mailboxlayer.com](https://mailboxlayer.com/) — Email validation and verification JSON API for developers. 1,000 free API requests/month
  * [mailcatcher.me](https://mailcatcher.me/) — Catches mail and serves it through a web interface
  * [mailchimp.com](https://mailchimp.com/) — 2,000 subscribers and 12,000 emails/month free
  * [MailerLite.com](https://www.mailerlite.com) — 1,000 subscribers/month, 12,000 emails/month free
  * [mailinator.com](https://www.mailinator.com/) — Free, public, email system where you can use any inbox you want
  * [mailjet.com](https://www.mailjet.com/) — 6,000 emails/month free (200 emails daily sending limit)
  * [mailkitchen](https://www.mailkitchen.com/) — Free for life without commitment, 10,000 emails/month, 1,000 emails/day
  * [Mailnesia](https://mailnesia.com) - Free temporary/disposable email, which auto visit registration link.
  * [mailsac.com](https://mailsac.com) - Free API for temporary email testing, free public email hosting, outbound capture, email-to-slack/websocket/webhook (1,500 monthly API limit)
  * [mailtrap.io](https://mailtrap.io/) — Fake SMTP server for development, free plan with 1 inbox, 50 messages, no team member, 2 emails/second, no forward rules
  * [mail7.io](https://www.mail7.io/) — Free Temp Email Addresses for QA Developers. Create email addresses instantly using Web Interface or API
  * [mohmal.com](https://www.mohmal.com/en) — Disposable temporary email
  * [moosend.com](https://moosend.com/) — Mailing list management service. Free account for 6 months for startups
  * [Outlook.com](https://outlook.live.com/owa/) - Free personal email and calendar
  * [pepipost.com](https://pepipost.com) — 30k emails free for first month, then first 100 emails/day free
  * [phplist.com](https://phplist.com/) — Hosted version allow 300 emails/month free
  * [postmarkapp.com](https://postmarkapp.com/) - 100 emails/month free, unlimited DMARC weekly digests
  * [Sender](https://www.sender.net) Up to 15 000 emails/month - Up to 2 500 subscribers
  * [sendgrid.com](https://sendgrid.com/) — 100 emails/day and 2,000 contacts free
  * [sendinblue.com](https://www.sendinblue.com/) — 9,000 emails/month free
  * [sendpulse.com](https://sendpulse.com) — 50 emails free/hour, first 12,000 emails/month free
  * [socketlabs.com](https://www.socketlabs.com) - 40k emails free for first month, then first 2000 emails/month free
  * [sparkpost.com](https://www.sparkpost.com/) — First 500 emails/month free
  * [Substack](https://substack.com) — Unlimited free newsletter service. Start paying when you charge for it.
  * [Tempmailo](https://tempmailo.com/) - Unlimited free temp email addresses. Autoexpire in two days.
  * [temp-mail.io](https://temp-mail.io) — Free disposable temporary email service with multiple emails at once and forwarding
  * [testmail.app](https://testmail.app/) - Automate end-to-end email tests with unlimited mailboxes and a GraphQL API. 100 emails/month free forever, unlimited free for open source.
  * [tinyletter.com](https://tinyletter.com/) — 5,000 subscribers/month free
  * [trashmail.com](https://www.trashmail.com) - Free disposable email addresses with forwarding and automatic address expiration
  * [Validator.Pizza](https://www.validator.pizza/) — Free API to detect disposable emails
  * [Verifalia](https://verifalia.com/email-verification-api) — Real-time email verification API with mailbox confirmation and disposable email address detector; 25 free email verifications/day.
  * [verimail.io](https://verimail.io/) — Bulk and API email verification service. 100 free verifications/month
  * [Yandex.Connect](https://connect.yandex.com/pdd/) — Free email and DNS hosting for up to 1,000 users
  * [yopmail.fr](http://www.yopmail.fr/en/) — Disposable email addresses
  * [Zoho](https://www.zoho.com) — Started as an e-mail provider but now provides a suite of services out of which some of them have free plans. List of services having free plans :
     - [Email](https://zoho.com/mail) Free for 5 users. 5GB/user & 25 MB attachment limit, 1 domain.
     - [Sprints](https://zoho.com/sprints) Free for 5 users,5 Projects & 500MB storage.
     - [Docs](https://zoho.com/docs) — Free for 5 users with 1 GB upload limit & 5GB storage. Zoho Office Suite (Writer,Sheets & Show) comes bundled with it.
     - [Projects](https://zoho.com/projects) — Free for 3 users, 2 projects & 10 MB attachment limit. Same plan applies to [Bugtracker](https://zoho.com/bugtracker).
     - [Connect](https://zoho.com/connect) — Team Collaboration free for 25 users with 3 groups, 3 custom apps, 3 Boards, 3 Manuals, 10 Integrations along with channels,events & forums.
     - [Meeting](https://zoho.com/meeting) — Meetings with upto 3 meeting participants & 10 Webinar attendees.
     - [Vault](https://zoho.com/vault) — Password Management free for Individuals.
     - [Showtime](https://zoho.com/showtime) — Yet another Meeting software for training for a remote session upto 5 attendees.
     - [Notebook](https://zoho.com/notebook) — A free alternative to Evernote.
     - [Wiki](https://zoho.com/wiki) — Free for 3 users with 50 MB storage, unlimited pages, zip backups, RSS & Atom feed, access controls & customisable CSS.
     - [Subscriptions](https://zoho.com/subscriptions) — Recurring Billing management free for 20 customers/subscriptions & 1 user with all the payment hosting done by Zoho themselves. Last 40 subscription metrics are stored 
     - [Checkout](https://zoho.com/checkout) — Product Billing management with 3 pages & up to 50 payments.
     - [Desk](https://zoho.com/desk) — Customer Support management with 3 agents and private knowledge base, email tickets. Integrates with [Assist](https://zoho.com/assist) for 1 remote technician & 5 unattended computers.
     - [Cliq](https://zoho.com/cliq) — Team chat software with 100 GB storage, unlimited users, 100 users per channel & SSO.
     - [Campaigns](https://zoho.com/campaigns)
     - [Forms](https://zoho.com/forms)
     - [Sign](https:/zoho.com/sign)
     - [Surveys](https://zoho.com/surveys)
     - [Bookings](https://zoho.com/bookings)
     - [Analytics](https://zoho.com/analytics)
  * [SimpleLogin](https://simplelogin.io/) – Open source, self-hostable email alias/forwarding solution. Free 5 Aliases, unlimited bandwith, unlimited reply/send. Free for educational staffs (student, researcher, etc).

## Font

  * [dafont](https://www.dafont.com/) - The fonts presented on this website are their authors' property, and are either freeware, shareware, demo versions or public domain.
  * [Everything Fonts](https://everythingfonts.com/) - Offers multiple tools; @font-face, Units Converter, Font Hinter and Font Submitter.
  * [Font Squirrel](https://www.fontsquirrel.com/) - Freeware fonts that is licensed for commercial work. Hand-selected these typefaces and presenting them in an easy-to-use format.
  * [Google Fonts](https://fonts.google.com/) - Lots of free fonts that are easy and quick to install in a website via a download or a link to Google's CDN.
  * [FontGet](https://www.fontget.com/) - Has a variety of fonts available to download and sorted neatly with tags.

## Forms

  * [99inbound.com](https://www.99inbound.com/) - Build forms and share them online. Get an email or Slack message for each submission. Free plan has 2 forms, 100 entries per month, basic email & Slack.
  * [Form.taxi](https://form.taxi/) — Endpoint for HTML forms submissions. With notifications, spam blocker and GDPR-compliant data processing. Free plan for basic usage.
  * [Formcake.com](https://formcake.com) - Form backend for devs, free plan allows unlimited forms, 100 submissions, Zapier integration. No libraries or dependencies required.
  * [Formcarry.com](https://formcarry.com) - HTTP POST Form endpoint, Free plan allows 100 submissions per month.
  * [formingo.co](https://www.formingo.co/)- Easy HTML forms for static websites, get started for free without registering an account. Free plan allows 500 submissions per month, customizable reply-to email address.
  * [formlets.com](https://formlets.com/) — Online forms, unlimited single page forms/month, 100 submissions/month, email notifications.
  * [formspark.io](https://formspark.io/) -  Form to Email service, free plan allows unlimited forms, 250 submissions per month, support by Customer assistance team.
  * [Formspree.io](https://formspree.io/) — Send email using an HTTP POST request. Free tier limits to 50 submissions per form per month.
  * [getform.io](https://getform.io/) - Form backend platform for designers and developers, 1 form, 50 submissions, Single file upload, 100MB file storage.
  * [Kwes.io](https://kwes.io/) - Feature rich form endpoint. Works great with static sites. Free plan includes up 1 website with up to 50 submissions per month.
  * [Qualtrics Survey](https://qualtrics.com/free-account) — Create professional forms & survey using this first class tool. 50+ expert-designed survey templates. Free Account has limit of 1 active survey, 100 responses/survey & 8 response types.
  * [Pageclip](https://pageclip.co/) - Free plan allows one site, one form, 1,000 submissions per month.
  * [smartforms.dev](https://smartforms.dev/) - Powerful and easy form backend for your website, forever free plan allows 50 submissions per month, 250MB file storage, Zapier integration, CSV/JSON export, custom redirect, custom response page, Telegram & Slack bot, single email notifications.
  * [staticforms.xyz](https://www.staticforms.xyz/) - Integrate HTML forms easily without any server side code for free. After user submits the form an email will be sent to your registered address with form content.
  * [Typeform.com](https://www.typeform.com/) — Include beautifully designed forms on websites.  Free plan allows only 10 fields per form and 100 responses per month.
  * [WaiverStevie.com](https://waiverstevie.com) - Electronic Signature platform with a REST API. Receive notifications with webhooks. Free plan watermarks signed documents, but allows unlimited envelopes + signatures.
  * [Wufoo](https://www.wufoo.com/) - Quick forms to use on websites. Free plan has a limit of 100 submissions each month.
  * [Web3Forms](https://web3forms.com) - Contact forms for Static & JAMStack Websites without writing backend code. Free plan allows Unlimited Forms, Unlimited Domains & 250 Submissions per month.

## CDN and Protection

  * [Arvan Cloud](https://arvancloud.com/) — Offers cloud related services (CDN,Cloud DNS, PaaS, Security etc.). Free plan offers :
    - CDN with Free SSL. 50 GB Traffic + 1 Million HTTP(S) Requests.
    - Free Cloud DNS for unlimited sites.
    - Free Cloud Security with Basic DDoS Protection + 5 Firewall Rules.
    - Free VoD (Video On Demand) Platform with 10 GB Storage + 50 GB Traffic.
  * [bootstrapcdn.com](https://www.bootstrapcdn.com/) — CDN for bootstrap, bootswatch and fontawesome.io
  * [cdnjs.com](https://cdnjs.com/) — CDN for JavaScript libraries, CSS libraries, SWF, images, etc.
  * [Cloudflare](https://www.cloudflare.com/)
    * CDN along with free SSL
    * Free DNS for unlimited number of domains
    * Firewall rules and pagerules
    * Analytics
    * [TryCloudflare](https://developers.cloudflare.com/argo-tunnel/trycloudflare) — Expose local HTTP servers through Argo Tunnel to public.
  * [ddos-guard.net](https://ddos-guard.net/store/web) — Free CDN, DDoS protection and SSL certificate
  * [developers.google.com](https://developers.google.com/speed/libraries/) — The Google Hosted Libraries is a content distribution network for the most popular, Open Source JavaScript libraries
  * [jare.io](http://www.jare.io) — CDN for images. Uses AWS CloudFront
  * [jsdelivr.com](https://www.jsdelivr.com/) — CDN of OSS (JS, CSS, fonts) for developers and webmasters, accepts PRs to add more
  * [Microsoft Ajax](https://docs.microsoft.com/en-us/aspnet/ajax/cdn/overview) — The Microsoft Ajax CDN hosts popular third-party JavaScript libraries such as jQuery and enables you to easily add them to your Web application
  * [netdepot.com](https://www.netdepot.com/cdn/) — First 100 GB free/month
  * [ovh.ie](https://www.ovh.ie/ssl-gateway/) — Free DDoS protection and SSL certificate
  * [PageCDN.com](https://pagecdn.com/) - Offers free Public CDN for everyone, and free Private CDN for opensource / nonprofits.
  * [Skypack](https://www.skypack.dev/) — The 100% Native ES Module JavaScript CDN. Free for 1 million requests per domain, per month.
  * [raw.githack.com](https://raw.githack.com/) — A modern replacement of **rawgit.com** which simply hosts file using Cloudflare
  * [section.io](https://www.section.io/) — A simple way to spin up and manage a complete Varnish Cache solution. Supposedly free forever for one site
  * [speeder.io](https://speeder.io/) — Uses KeyCDN. Automatic image optimization and free CDN boost. Free and does not require any server changes
  * [staticaly.com](https://staticaly.com/) — CDN for Git repos (GitHub, GitLab, Bitbucket), WordPress-related assets and images
  * [toranproxy.com](https://toranproxy.com/) — Proxy for Packagist and GitHub. Never fail CD. Free for personal use, 1 developer, no support
  * [unpkg.com](https://unpkg.com/) — CDN for everything on npm
  * [Namecheap Supersonic](https://www.namecheap.com/supersonic-cdn/#free-plan) — Free DDoS protection

## PaaS

  * [anvil.works](https://anvil.works) - Web app development with nothing but Python. Free tier with unlimited apps.
  * [appharbor.com](https://appharbor.com/) — A .Net PaaS that provides 1 free worker
  * [configure.it](https://www.configure.it/) — Mobile app development platform, free for 2 projects, limited features but no resource limits
  * [codenameone.com](https://www.codenameone.com/) — Open source, cross platform, mobile app development toolchain for Java/Kotlin developers. Free for commercial use with unlimited number of projects
  * [Deta](https://www.deta.sh) – Deploy unlimited number of Node.js and Python apps for free up to 50k requests/month. Includes free DBs, Auth and email.
  * [dronahq.com](https://www.dronahq.com/) — No code application development platform for enterprises to visually develop application, integrate with existing systems to Build internal apps, processes and forms, rapidly. Free plan offers 200 Tasks/month, Unlimited Draft Apps and 1 Published Apps
  * [encore.dev](https://encore.dev/) — Backend framework using static analysis to provide automatic infrastructure, boilerplate free code, and more. Includes free cloud hosting for hobby projects.
  * [firebase.google.com](https://firebase.google.com) — Build real-time apps, the free plan has 100 max connections, 10 GB data transfer, 1 GB data storage, 1 GB hosting storage and 10 GB hosting transfer
  * [gearhost.com](https://www.gearhost.com/pricing) — Platform for .NET and PHP apps. 256 MB of RAM for free on a shared server with limited resources
  * [gigalixir.com](https://gigalixir.com/) - Gigalixir provide 1 free instance that never sleeps, and free-tier PostgreSQL database limited to 2 connections, 10, 000 rows and no backups, for Elixir/Phoenix apps.
  * [glitch.com](https://glitch.com/) — Free public/private hosting with features such as code sharing and real-time collaboration. Free plan has 1000 hours/month limit.
  * [heroku.com](https://www.heroku.com/) — Host your apps in the cloud, free for single process apps
  * [Krucible](https://usekrucible.com) — Krucible is a platform for creating Kubernetes clusters for testing and development. Free tier accounts come with 25 cluster-hours per month.
  * [ZARVIS](https://zarvis.ai) - Free managed Kubernetes namespace for open source Github project. Free 1GB memory and 1 vCPU.
  * [Mendix](https://www.mendix.com/) — Rapid Application Development for Enterprises, unlimited number of free sandbox environments supporting unlimited users, 0.5 GB storage and 1 GB RAM per app. Also Studio and Studio Pro IDEs are allowed in free tier.
  * [m3o.com](https://m3o.com) - A cloud platform for API services development. M3O is a fully managed Micro as a Service offering focusing on Go microservices development in the Cloud. Free tier provides enough to run 5 services and collaborate with others.
  * [Okteto Cloud](https://okteto.com) - Managed Kubernetes service designed for remote development. Free developer accounts come with 8GB of RAM, 4 CPUs and 5GB Disk space. The apps sleep after 24 hours of inactivity.
  * [opeNode](https://openode.io) — Free Node.js hosting for Open Source projects. 100 GB Bandwidth/month with 100 MB memory & 1000 MB storage. Deploy using CLI or existing Git repository.
  * [outsystems.com](https://www.outsystems.com/) — Enterprise web development PaaS for on-premise or cloud, free "personal environment" offering allows for unlimited code and up to 1 GB database
  * [pipedream.com](https://pipedream.com) - An integration platform built for developers. Develop any workflow, based on any trigger. Workflows are code, which you can run [for free](https://docs.pipedream.com/pricing/). No server or cloud resources to manage.
  * [pythonanywhere.com](https://www.pythonanywhere.com/) — Cloud Python app hosting. Beginner account is free, 1 Python web application at your-username.pythonanywhere.com domain, 512 MB private file storage, one MySQL database
  * [scn.sap.com](https://scn.sap.com/docs/DOC-56411) — The in-memory Platform-as-a-Service offering from SAP. Free developer accounts come with 1 GB structured, 1 GB unstructured, 1 GB of Git data and allow you to run HTML5, Java and HANA XS apps
  * [staroid.com](https://staroid.com) - Managed Kubernetes namespace service designed to fund open source developers. Free 8 CPUs and 16GB of RAM namespace to test branches and pull requests of public repository. Free test namespace shutdown every 30 minutes. Maximum 2 concurrent test namespaces.
  * [SUSE Developer Program](https://developer.suse.com) — Experience cloud native productivity for free. Get hands-on with the SUSE Cloud Application Platform with your own Developer Sandbox. 1 Free Application. Free subdomain provided along with API for CLI. Storage & Memory Quota of 1 GB.
  * [workers.dev](https://workers.dev) - Deploy serverless code for free on Cloudflare's global network. 100,000 free requests per day with a workers.dev subdomain.
  * [Platform9](https://platform9.com/) - Managed Kubernetes service designed for developers. Free developer accounts come with up to 3 clusters & 20 nodes cluster.
  * [fly.io](https://fly.io/) - Fly is a platform for applications that need to run globally. It runs your code close to users and scales compute in cities where your app is busiest. Write your code, package it into a Docker image, deploy it to Fly's platform and let that do all the work to keep your app snappy. Free for side projects, $10/mo of service credit that automatically applies to any paid service. And if you ran really small virtual machines, credits will go a long way.
  * [appfleet.com](https://appfleet.com/) - appfleet is an edge platform that allows its users to deploy containers globally to multiple regions at the same time. It offers a simple to use UI while automating all the complexity like smart routing, clustering, failover, monitoring and so on. It’s free for open source projects and all users automatically get $10 to host whatever they want.
  * [Divio](https://www.divio.com/) - A platform to manage cloud application deploying only using Docker. Available free subscription for development projects.
  * [Koyeb](https://www.koyeb.com) - Koyeb is a developer-friendly serverless platform to deploy apps globally. Seamlessly run Docker containers, web apps, and APIs with git-based deployment, native autoscaling, a global edge network, and built-in service mesh and discovery. Koyeb provides two nano services to run your apps with its forever-free tier and also sponsors open-source projects with free resources.

## BaaS

  * [ably.com](https://www.ably.com) - APIs for realtime messaging, push notifications, and event-driven API creation. Free plan has 3m messages/mo, 100 concurrent connections, 100 concurrent channels.
  * [back4app.com](https://www.back4app.com) - Back4App is an easy-to-use, flexible and scalable backend based on Parse Platform.
  * [backendless.com](https://backendless.com/) — Mobile and Web Baas, with 1 GB file storage free, push notifications 50000/month, and 1000 data objects in table.
  * [blockspring.com](https://www.blockspring.com/) — Cloud functions. Free for 5 million runs/month
  * [BMC Developer Program](https://developers.bmc.com/site/global/bmc_helix_platform/program/overview/index.gsp) — The BMC Developer Program provides documentation and resources to build and deploy digital innovations for your enterprise. Access to a comprehensive, personal sandbox which includes the platform, SDK, and a library of components that can be used to build and tailor apps.
  * [darklang.com](https://darklang.com/) - Hosted language combined with editor and infrastructure. Free during the beta, generous free tier planned after beta.
  * [getstream.io](https://getstream.io/) — Build scalable news feeds and activity streams in a few hours instead of weeks, free for 3 million feed updates/month
  * [hasura.io](https://hasura.io/) — Platform to build and deploy app backends fast, free for single node cluster.
  * [iron.io](https://www.iron.io/) — Async task processing (like AWS Lambda) with free tier and 1-month free trial
  * [netlicensing.io](https://netlicensing.io) - A cost-effective and integrated Licensing-as-a-Service (LaaS) solution for your software on any platform from Desktop to IoT and SaaS. Basic Plan for *FREE* while you are a student.
  * [onesignal.com](https://onesignal.com/) — Unlimited free push notifications
  * [paraio.com](https://paraio.com) — Backend service API with flexible authentication, full-text search and caching. Free for 1 app, 1GB app data.
  * [posthook.io](https://posthook.io/) — Job Scheduling Service. Allows you to schedule requests for specific times. 500 scheduled requests/month free.
  * [progress.com](https://www.progress.com/kinvey) — Mobile backend, starter plan has unlimited requests/second, with 1 GB of data storage. Enterprise application support
  * [pubnub.com](https://www.pubnub.com/) — Free push notifications for up to 1 million messages/month and 100 active daily devices
  * [pushbots.com](https://pushbots.com/) — Push notification service. Free for up to 1.5 million pushes/month
  * [pushcrew.com](https://pushcrew.com/) — Push notification service. Unlimited notifications up to 2000 Subscribers
  * [pusher.com](https://pusher.com/beams) — Free, unlimited push notifications for 2000 monthly active users. A single API for iOS and Android devices.
  * [pushtechnology.com](https://www.pushtechnology.com/) — Real-time Messaging for browsers, smartphones and everyone. 100 concurrent connections. Free 10 GB data/month
  * [quickblox.com](https://quickblox.com/) — A communication backend for instant messaging, video and voice calling and push notifications
  * [restspace.io](https://restspace.io/) - Configure a server with services for auth, data, files, email API, templates etc, then compose into pipelines and transform data.
  * [Salesforce Developer Program](https://developer.salesforce.com/signup) — Build apps Lightning fast with drag and drop tools. Customize your data model with clicks. Go further with Apex code. Integrate with anything using powerful APIs. Stay protected with enterprise-grade security. Customize UI with clicks or any leading-edge web framework. Free Developer Program gives access to the full Lightining Platform.
  * [ServiceNow Developer Program](https://developer.servicenow.com/) — Rapidly build, test, and deploy applications that make work better for your organization. Free Instance & access early previews.
  * [simperium.com](https://simperium.com/) — Move data everywhere instantly and automatically, multi-platform, unlimited sending and storage of structured data, max. 2,500 users/month
  * [stackstorm.com](https://stackstorm.com/) — Event-driven automation for apps, services and workflows, free without flow, access control, LDAP,...
  * [streamdata.io](https://streamdata.io/) — Turns any REST API into an event-driven streaming API. Free plan up to 1 million messages and 10 concurrent connections
  * [tyk.io](https://tyk.io/) — API management with authentication, quotas, monitoring and analytics. Free cloud offering
  * [zapier.com](https://zapier.com/) — Connect the apps you use, to automate tasks. 5 zaps, every 15 minutes and 100 tasks/month
  * [LeanCloud](https://leancloud.app/) — Mobile backend. 1GB of data storage, 256MB instance, 3K API requests/day, 10K pushes/day are free. (API is very similar to Parse Platform)
  * [Liteflow](https://liteflow.com/) - Low-code development toolkit built to help you focus on your app’s real value.

## Web Hosting

  * [000WebHost](https://www.000webhost.com/) — Zero cost website hosting with Apache, PHP, MySQL, cPanel with ads on the bottom of each pages!
  * [20i](https://www.20i.com/) — Free web hosting with no ads, on the same platform as paid plans. Includes a free CDN, 100 email addresses, SSL and over 80 one-click installs.
  * [Alwaysdata](https://www.alwaysdata.com/) — 100 MB free web hosting with support for MySQL, PostgreSQL, CouchDB, MongoDB, PHP, Python, Ruby, Node.js, Elixir, Java, Deno, custom web servers, access via FTP, WebDAV and SSH; mailbox, mailing list and app installer included.
  * [Awardspace.com](https://www.awardspace.com) — Free web hosting + a free short domain, PHP, MySQL, App Installer, Email Sending & No Ads.
  * [Bubble](https://bubble.io/) — Visual programming to build web and mobile apps without code, free with Bubble branding.
  * [Byet](https://byet.host) — Byet provides you with a massive free, and ad-free load balanced free web hosting service including PHP, MySQL, FTP, Vistapanel & more!..
  * [cloudno.de](https://cloudno.de/) — Free cloud hosting for Node.js apps.
  * [Drive To Web](https://drv.tw) — Host directly to the web from Google Drive & OneDrive. Static sites only. Free forever. One site per Google/Microsoft account.
  * [Endless Hosting](https://theendlessweb.com/) — 300 MB storage, Free SSL, PHP, MySQL, FTP, free sub-domains, E-Mail, DNS, beatiful panel UI. One of the best!
  * [Fenix Web Server](https://preview.fenixwebserver.com) - A developer desktop app for hosting sites locally and sharing them publically (in realtime). Work however you like, using its beautiful user interface, API, and/or CLI.
  * [Free Hosting](http://freehostingnoads.net/) — Free Hosting With PHP 5, Perl, CGI, MySQL, FTP, File Manager, POP E-Mail, free sub-domains, free domain hosting, DNS Zone Editor, Web Site Statistics, FREE Online Support and many more features not offered by other free hosts.
  * [Freehostia](https://www.freehostia.com) — FreeHostia offers free hosting services incl. an industry-best Control Panel & a 1-click installation of 50+ free apps. Instant setup. No forced ads.
  * [heliohost.org](https://www.heliohost.org) — Community powered free hosting for everyone.
  * [hostman.com](https://hostman.com) — Deploy up to 3 static sites from your GitHub repository for free.
  * [InfinityFree](https://infinityfree.net/) - Free PHP website hosting with MySQL, cPanel, and no ads.
  * [neocities.org](https://neocities.org) — Static, 1 GB free storage with 200 GB Bandwidth.
  * [netlify.com](https://www.netlify.com/) — Builds, deploy and hosts static site/app free for, 100 GB data and 100 GB/month bandwidth.
  * [commons.host](https://commons.host/) - Static web hosting and CDN.100% free and open source software (FOSS). With a commercially sustainable software as a service (SaaS) to fund R&D.
  * [pantheon.io](https://pantheon.io/) — Drupal and WordPress hosting, automated DevOps and scalable infrastructure. Free for developers and agencies
  * [pony.icu](https://pony.icu/) — Free Web Hosting with Unlimited Disk Space, Unlimited Bandwidth and Unlimited Websites from PonyICU. PHP and MySQL included.
  * [readthedocs.org](https://readthedocs.org/) — Free documentation hosting with versioning, PDF generation and more
  * [render.com](https://render.com) — A unified platform to build and run all your apps and web app free SSL, a global CDN, private networks and auto deploys from Git, free for static web page.
  * [sourceforge.net](https://sourceforge.net/) — Find, Create and Publish Open Source software for free
  * [surge.sh](https://surge.sh/) — Static web publishing for Front-End developers. Unlimited sites with custom domain support
  * [tilda.cc](https://tilda.cc/) — One site, 50 pages, 50 MB storage, only the main pre-defined blocks among 170+ available, no fonts, no favicon and no custom domain
  * [txti.es](https://txti.es/) — Quickly create web pages with markdown.
  * [Vercel](https://vercel.com/) — Build, deploy, and host web apps with free SSL, global CDN, and unique Preview URLs each time you `git push`. Perfect for Next.js and other Static Site Generators.
  * [Versoly](https://versoly.com/) — SaaS focussed website builder - unlimited websites, 70+ blocks, 5 templates, custom CSS, favicon, SEO and forms. No custom domain.
  * [Qovery](https://www.qovery.com) — Qovery is the simplest way to deploy your full-stack apps on AWS, GCP and Azure. It is free web hosting for developers with Database, SSL, a global CDN, and auto deploys from Git.
  * [0hi.me](https://0hi.me/) — Free PHP & MySQL Web Hosting for your small project. SSL/TLS and CDN also available for free.

## DNS

  * [1984.is](https://www.1984.is/product/freedns/) — Free DNS service with API, and lots of other free DNS features included.
  * [biz.mail.ru](https://biz.mail.ru) — Free email and DNS hosting for up to 5,000 users
  * [cloudns.net](https://www.cloudns.net/) — Free DNS hosting up to 1 domain with 50 records
  * [dns.he.net](https://dns.he.net/) — Free DNS hosting service with Dynamic DNS Support
  * [dnspod.com](https://www.dnspod.com/) — Free DNS hosting.
  * [duckdns.org](https://www.duckdns.org/) — Free DDNS with up to 5 domains on the free tier. With configuration guides for various setups.
  * [dynu.com](https://www.dynu.com/) — Free dynamic DNS service
  * [fosshost.org](https://fosshost.org/) - Free open source hosting VPS, web, storage and mirror hosting
  * [freedns.afraid.org](https://freedns.afraid.org/) — Free DNS hosting. Also provide free subdomain based on numerous public user [contributed domains](https://freedns.afraid.org/domain/registry/). Get free subdomains from "Subdomains" menu after signing up.
  * [freenom.com](https://freenom.com/) — Free domain provider. Get FQDN for free.
  * [luadns.com](https://www.luadns.com/) — Free DNS hosting, 3 domains, all features with reasonable limits
  * [namecheap.com](https://www.namecheap.com/domains/freedns/) — Free DNS. No limit on number of domains
  * [nextdns.io](https://nextdns.io) - DNS based firewall, 300K free queries monthly
  * [noip](https://www.noip.com/) — a dynamic dns service that allows up to 3 hostnames free with confirmation every 30 days
  * [ns1.com](https://ns1.com/) — Data Driven DNS, automatic traffic management, 500k free queries
  * [pointhq.com](https://pointhq.com/developer) — Free DNS hosting on Heroku.
  * [selectel.com](https://selectel.com/services/dns/) — Free DNS hosting, anycast
  * [web.gratisdns.dk](https://web.gratisdns.dk/domaener/dns/) — Free DNS hosting.
  * [Yandex.Connect](https://connect.yandex.com/pdd/) — Free email and DNS hosting for up to 1,000 users
  * [zilore.com](https://zilore.com/en/dns) — Free DNS hosting.
  * [zoneedit.com](https://www.zoneedit.com/free-dns/) — Free DNS hosting with Dynamic DNS Support.
  * [zonewatcher.com](https://zonewatcher.com) — Automatic backups and DNS change monitoring. 1 domain free
  * [huaweicloud.com](https://www.huaweicloud.com/intl/en-us/product/dns.html) – Free DNS hosting by Huawei
  * [Hetzner](https://www.hetzner.com/dns-console) – Free DNS hosting from Hetzner with API support
  * [Glauca](https://docs.glauca.digital/hexdns/) – Free DNS hosting for up to 3 domains and DNSSEC support
  * [F5](https://www.f5.com/products/ways-to-deploy/cloud-services/dns-cloud-service) – Free Anycast DNS hosting for primary zones. And free for secondary zones up to 1 domain and 3 million requests per month.

## IaaS

  * [backblaze.com](https://www.backblaze.com/b2/) — Backblaze B2 cloud storage. Free 10 GB (Amazon S3-like) object storage for unlimited time
  * [scaleway.com](https://www.scaleway.com/en/object-storage/) — S3-Compatible Object Storage. Free 75 GB storage and external outgoing traffic
  * [terraform.io](https://www.terraform.io/) — Terraform Cloud. Free remote state management and team collaboration for teams up to 5 users.

## DBaaS

   * [airtable.com](https://airtable.com/) — Looks like a spreadsheet, but it's a relational database, unlimited bases, 1,200 rows/base and 1,000 API requests/month
   * [Astra](https://astra.datastax.com/register) — Cloud Native Cassandra as a Service with 5GB free tier
   * [cloudamqp.com](https://www.cloudamqp.com/) — RabbitMQ as a Service, up to 1M messages/month and 20 connections free
   * [elephantsql.com](https://www.elephantsql.com/) — PostgreSQL as a service, 20 MB free
   * [FaunaDB](https://fauna.com/) — Serverless cloud database, with native GraphQL, multi-model access and daily free tiers up to 100 MB
   * [graphenedb.com](https://www.graphenedb.com/) — Neo4j as a service, up to 1,000 nodes and 10,000 relations free
   * [heroku.com](https://www.heroku.com/) — PostgreSQL as a service, up to 10,000 rows and 20 connections free (provided as an "addon," but can be attached to an otherwise empty app and accessed externally)
   * [Upstash](https://upstash.com/) — Serverless Redis with free tier up to 10,000 requests per day, 256MB max database size, and 20 concurrent connections
   * [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) — free tier gives 512 MB
   * [redsmin.com](https://www.redsmin.com/) — Online real-time monitoring and administration service for Redis, Monitoring for 1 Redis instance free
   * [redislabs](https://redislabs.com/try-free/) - Free 30Mb redis instance
   * [MemCachier](https://www.memcachier.com/) — Managed Memcache service. Free for up to 25MB, 1 Proxy Server and basic analytics
   * [scalingo.com](https://scalingo.com/) — Primarily a PaaS but offers a 128MB to 192MB free tier of MySQL, PostgreSQL or MongoDB
   * [SeaTable](https://seatable.io/) — Flexible, Spreadsheet-like Database built by Seafile team. unlimited tables, 2,000 lines, 1-month versioning, up to 25 team members.
   * [skyvia.com](https://skyvia.com/) — Cloud Data Platform, offers free tier and all plans are completely free while in beta
   * [StackBy](https://stackby.com/) — One tool that brings together flexibility of spreadsheets, power of databases and built-in integrations with your favorite business apps. Free plan includes unlimited users, 10 stacks, 2GB attachment per stack.
   * [InfluxDB](https://www.influxdata.com/) — Timeseries database, free up to 3MB/5 minutes writes, 30MB/5 minutes reads and 10,000 cardinalities series
   * [Quickmetrics](https://www.quickmetrics.io/) — Timeseries database with dashboard included, free up to 10,000 events/day and total of 5 metrics.
   * [restdb.io](https://restdb.io/) - a fast and simple NoSQL cloud database service. With restdb.io you get schema, relations, automatic REST API (with MongoDB-like queries) and an efficient multi-user admin UI for working with data. Free plan allows 3 users, 2500 records and 1 API requests per second.

## STUN, WebRTC, Web Socket Servers and Other Routers

   * [conveyor.cloud](https://conveyor.cloud/) — Visual Studio extension to expose IIS Express to the local network or over a tunnel to a public URL.
   * [Hamachi](https://www.vpn.net/) — LogMeIn Hamachi is a hosted VPN service that lets you securely extend LAN-like networks to distributed teams with free plan allows unlimited networks with up to 5 peoples
   * [Radmin VPN](https://www.radmin-vpn.com/) - Connect multiple computers together via a VPN enabling LAN-like networks. Unlimited peers. (Hamachi alternative)
   * [localhost.run](https://localhost.run/) — Instantly share your localhost environment! No download required. Run your app on port 8080 and then run this command and share the URL.
   * [ngrok.com](https://ngrok.com/) — Expose locally running servers over a tunnel to a public URL.
   * [segment.com](https://segment.com/) — Hub to translate and route events to other third-party services. 100,000 events/month free
   * [stun:global.stun.twilio.com:3478?transport=udp](stun:global.stun.twilio.com:3478?transport=udp) — Twilio STUN
   * [stun:stun.l.google.com:19302](stun:stun.l.google.com:19302) — Google STUN
   * [webhookrelay.com](https://webhookrelay.com) — Manage, debug, fan-out and proxy all your webhooks to public or internal (ie: localhost) destinations. Also, expose servers running in a private network over a tunnel by getting a public HTTP endpoint (`https://yoursubdomain.webrelay.io <----> http://localhost:8080`).
   * [Xirsys](https://www.xirsys.com) — Global network of STUN / TURN servers with a generous free tier.
   * [ZeroTier](https://www.zerotier.com) — FOSS managed virtual Ethernet as a service. Unlimited end-to-end encrypted networks of 100 clients on free plan. Clients for desktop/mobile/NA; web interface for configuration of custom routing rules and approval of new client nodes on private networks.

## Issue Tracking and Project Management

   * [acunote.com](https://www.acunote.com/) — Free project management and SCRUM software for up to 5 team members
   * [AppFlux](https://appflux.io) — Project Management tool with Log Management & Issues. Take your team onboard & forget management through emails.
   * [asana.com](https://asana.com/) — Free for private project with collaborators
   * [Basecamp](https://basecamp.com/personal) - To-do lists, milestone management, forum-like messaging, file sharing, and time tracking. Up to 3 projects, 20 users, and 1GB of storage space.
   * [bitrix24.com](https://www.bitrix24.com/) — Free intranet and project management tool
   * [cacoo.com](https://cacoo.com/) — Online diagrams in real-time: flowchart, UML, network. Free max. 15 users/diagram, 25 sheets
   * [clickup.com](https://clickup.com/) — Project management. Free, premium version with cloud storage. Mobile applications and Git integrations available
   * [Cloudcraft](https://cloudcraft.co/) — Design a professional architecture diagram in minutes with the Cloudcraft visual designer, optimized for AWS with smart components that show live data too.
   * [Clubhouse](https://clubhouse.io/) - Project management platform. Free for up to 10 users forever
   * [Codegiant](https://codegiant.io) — Project Management with Repository hosting & CI/CD. Free Plan Offers Unlimited Repositories,Projects & Documents with 5 Team Members. 500 CI/CD minutes per month. 30000 Serverless Code Run minutes per month.1GB repository storage.
   * [Confluence](https://www.atlassian.com/software/confluence) - Atlassian's content collaboration tool used to help teams collaborate and share knowledge efficiently. Free plan up to 10 users.
   * [contriber.com](https://www.contriber.com/) — Customizable project management platform, free starter plan, 5 workspaces
   * [draw.io](https://www.draw.io/) — Online diagrams stored locally, in Google Drive, OneDrive or Dropbox. Free for all features and storage levels
   * [freedcamp.com](https://freedcamp.com/) - tasks, discussions, milestones, time tracking, calendar, files and password manager. Free plan with unlimited projects, users and files storage.
   * [easyretro.io](https://www.easyretro.io/) — Free simple and intuitive sprint retrospective tool
   * [gleek.io](https://www.gleek.io) — Free description-to-diagrams tool for developers. Create informal, UML class, object, or entity-relationship diagrams using your keyword.
   * [gliffy.com](https://www.gliffy.com/) — Online diagrams: flowchart, UML, wireframe,... Also plugins for Jira and Confluence. 5 diagrams and 2 MB free
   * [GraphQL Inspector](https://github.com/marketplace/graphql-inspector) - GraphQL Inspector ouputs a list of changes between two GraphQL schemas. Every change is precisely explained and marked as breaking, non-breaking or dangerous.
   * [huboard.com](https://huboard.com/) — Instant project management for your GitHub issues, free for Open Source
   * [Instabug](https://instabug.com) —  A comprehensive bug reporting and in-app feedback SDK for mobile apps. Free plan up to 1 app and 1 member.
   * [Ilograph](https://www.ilograph.com/)  — interactive diagrams that allow users to see their infrastructure from multiple perspectives and levels of detail. Diagrams can be expressed in code. Free tier has unlimited private diagrams with up to 3 viewers.
   * [Issue Embed](https://issueembed.dev/) - A bug reporting tool for websites to go directly into your Github Issues. Free plan for personal repositories with up to 500 issues/month and 10,000 page views/month.
   * [Jira](https://www.atlassian.com/software/jira) — Advanced software development project management tool used in many corporate environments. Free plan up to 10 users.
   * [kanbanflow.com](https://kanbanflow.com/) — Board-based project management. Free, premium version with more options
   * [kanbantool.com](https://kanbantool.com/) — Kanban board-based project management. Free, paid plans with more options
   * [Kitemaker.co](https://kitemaker.co) - Collaborate through all phases of the product development process and keep track of work across Slack, Discord, Figma, and Github. Unlimited users, unlimited spaces. Free plan up to 250 work items.
   * [kanrails.com](https://kanrails.com/) — Kanban board-based project management. Free for 3 collaborators, 2 projects and 5 tracks. Paid plans available for unlimited collaborators, projects and tracks.
   * [Kumu.io](https://kumu.io/)  — Relationship maps with animation, decorations, filters, clustering, spreadsheet imports and more. Free tier allows unlimited public projects. Graph size unlimited. Free private projects for students. Sandbox mode is available if you prefer to not leave your file publicly online (upload, edit, download, discard).
   * [LeanBoard](https://www.leanboard.io) — Collaborative whiteboard with sticky notes for your GitHub issues (Useful for Example Mapping and other techniques)
   * [Linear](https://linear.app/) — Issue tracker with streamlined interface. Free for unlimited members, up to 10MB file upload size, 250 issues (excluding Archive)
   * [MeisterTask](https://www.meistertask.com/) — Online task management for teams. Free up to 3 projects, unlimited project members.
   * [MeuScrum](https://www.meuscrum.com/en) - Free online scrum tool with kanban board
   * [Ora](https://ora.pm/) - Agile task management & team collaboration. Free for up to 3 users and files are limited to 10 MB.
   * [pivotaltracker.com](https://www.pivotaltracker.com/) — Free for unlimited public projects and two private projects with 3 total active users (read-write) and unlimited passive users (read-only).
   * [plan.io](https://plan.io/) — Project Management with Repository Hosting and more options. Free for 2 users with 10 customers and 500MB Storage
   * [planitpoker.com](https://www.planitpoker.com/) — Free online planning poker (estimation tool)
   * [senseitool.com](https://www.senseitool.com/) — An agile retrospective tool - Free.
   * [SpeedBoard](https://speedboard.app) - Board for Agile and Scrum retrospectives - Free.
   * [Tadum](https://tadum.app) - Meeting agenda and minutes app designed for recurring meetings, free for teams up to 10
   * [taiga.io](https://taiga.io/) — Project management platform for startups and agile developers, free for Open Source
   * [Tara AI](https://tara.ai/) — Simple sprint management service. Free plan has unlimited tasks, sprints and workspaces, with no user limits.
   * [targetprocess.com](https://www.targetprocess.com/) — Visual project management, from Kanban and Scrum to almost any operational process. Free for unlimited users, up to 1,000 data entities {[more details](https://www.targetprocess.com/pricing/)}
   * [taskade.com](https://www.taskade.com/) — Real-time collaborative task lists and outlines for teams
   * [taskulu.com](https://taskulu.com/) — Role based project management. Free up to 5 users. Integration with GitHub/Trello/Dropbox/Google Drive
   * [teamwork.com](https://teamwork.com/) — Project management & Team Chat. Free for 5 users and 2 projects. Premium plans available.
   * [testlio.com](https://testlio.com/) — Issue tracking, test management and beta testing platform. Free for private use
   * [terrastruct.com](https://terrastruct.com/) — Online diagram maker specifically for software architecture. Free tier up to 4 layers per diagram.
   * [todoist.com](https://todoist.com/) — Collaborative and individual task management. Free, Premium and Team plans are available. Discounts provided for eligible users.
   * [trello.com](https://trello.com/) — Board-based project management. Unlimited Personal Boards, 10 Team Boards.
   * [Tweek](https://tweek.so/) — Simple Weekly To-Do Calendar & Task Management.
   * [ubertesters.com](https://ubertesters.com/) — Test platform, integration and crowdtesters, 2 projects, 5 members
   * [vabotu](https://vabotu.com/) - A collaborative tool for project management. Free and other plans are avaiable. The Freelance plan is for 10 users, include messaging, task-boards, 5GB online storage, workspaces, export data.
   * [vivifyscrum.com](https://www.vivifyscrum.com/) — Free tool for Agile project management. Scrum Compatible
   * [Yodiz](https://www.yodiz.com/) — Agile development and issue tracking. Free up to 3 users, unlimited projects.
   * [YouTrack](https://www.jetbrains.com/youtrack/buy/#edition=incloud) — Free hosted YouTrack (InCloud) for FOSS projects, private projects (free for 3 users). Includes time tracking and agile boards
   * [zenhub.com](https://www.zenhub.com) — The only project management solution inside GitHub. Free for public repos, OSS and nonprofit organizations
   * [zepel.io](https://zepel.io/) - The project management tool that lets you plan features, collaborate across disciplines, and build software together. Free up to 5 members. No feature restrictions.
   * [zenkit.com](https://zenkit.com) — Project management and collaboration tool. Free for up to 5 members, 5 GB attachments.
   * [Zube](https://zube.io) — Project management with free plan for 4 Projects & 4 users. GitHub integration available.

## Storage and Media Processing

   * [borgbase.com](https://www.borgbase.com/) — Simple and secure offsite backup hosting for Borg Backup. 10 GB free backup space and 2 repositories.
   * [sirv.com](https://sirv.com/) — Smart Image CDN with on-the-fly image optimization and resizing. Free tier includes 500 MB of storage and 2 GB bandwidth.
   * [image4.io](https://image4.io/) — Image upload, powerful manipulations, storage and delivery for websites and apps, with SDK's, integrations and migration tools. Free tier includes 25 credits. 1 credit is equal to 1 GB of CDN usage, 1GB of storage or 1000 image transformations.
   * [cloudimage.com](https://cloudimage.com/) — Full image optimization and CDN service with 1500+ Points of Presence around the world. A variety of image resizing, compression, watermarking functions. Open source plugins for responsive images, 360 image making and image editing. Free monthly plan with 25GB of CDN traffic and 25GB of cache storage and unlimited transformations.
   * [cloudinary.com](https://cloudinary.com/) — Image upload, powerful manipulations, storage and delivery for sites and apps, with libraries for Ruby, Python, Java, PHP, Objective-C and more. Free tier includes 25 monthly credits. 1 credit is equal to 1,000 image transformations, 1 GB of storage, or 1 GB of CDN usage.
   * [easyDB.io](https://easydb.io/) — one-click, hosted database provider. They provide a database for the programming language of your choice for development purposes. The DB is ephemeral and will be deleted after 24 or 72 hours on the free tier.
   * [embed.ly](https://embed.ly/) — Provides APIs for embedding media in a webpage, responsive image scaling, extracting elements from a webpage. Free for up to 5,000 URLs/month at 15 requests/second
   * [filestack.com](https://www.filestack.com/) — File picker, transform and deliver, free for 250 files, 500 transformations and 3 GB bandwidth
   * [gumlet.com](https://www.gumlet.com/) — Image resize-as-a-service. It also optimizes images and performs delivery via CDN. Free tier includes 1 GB bandwidth and unlimited number of image processing every month for 1 year.
   * [image-charts.com](https://www.image-charts.com/) — Unlimited image chart generation with a watermark
   * [jsonbin.io](https://jsonbin.io/) — Free JSON data storage service, ideal for small-scale web apps, website, mobile apps.
   * [kraken.io](https://kraken.io/) — Image optimization for website performance as a service, free plan up to 1 MB file size
   * [npoint.io](https://www.npoint.io/) — JSON store with collaborative schema editing
   * [otixo.com](https://www.otixo.com/) — Encrypt, share, copy and move all your cloud storage files from one place. Basic plan provides unlimited files transfer with 250 MB max. file size and allows 5 encrypted files
   * [packagecloud.io](https://packagecloud.io/) — Hosted Package Repositories for YUM, APT, RubyGem and PyPI.  Limited free plans, open source plans available via request
   * [piio.co](https://piio.co/) — Responsive image optimization and delivery for every website. Free plan for developers and personal websites. Includes free CDN, WebP and Lazy Loading out of the box.
   * [Pinata IPFS](https://pinata.cloud) — Pinata is the simplest way to upload and manage files on IPFS. Our friendly user interface combined with our IPFS API makes Pinata the easiest IPFS pinning service for platforms, creators, and collectors. 1 GB storage free along with access to API.
   * [placeholder.com](https://placeholder.com/) — A quick and simple image placeholder service
   * [placekitten.com](https://placekitten.com/) — A quick and simple service for getting pictures of kittens for use as placeholders
   * [plot.ly](https://plot.ly/) — Graph and share your data. Free tier includes unlimited public files and 10 private files
   * [podio.com](https://podio.com/) — You can use Podio with a team of up to five people and try out the features of the Basic Plan, except user management
   * [QuickChart](https://quickchart.io) — Generate embeddable image charts, graphs, and QR codes
   * [redbooth.com](https://redbooth.com) — P2P file syncing, free for up to 2 users
   * [shrinkray.io](https://shrinkray.io/) — Free image optimization of GitHub repos
   * [tinypng.com](https://tinypng.com/) — API to compress and resize PNG and JPEG images, offers 500 compressions for free each month
   * [transloadit.com](https://transloadit.com/) — Handles file uploads and encoding of video, audio, images, documents. Free for Open source, charities, and students via the GitHub Student Developer Pack. Commercial applications get 2 GB free for test driving
   * [uploadcare.com](https://uploadcare.com/hub/developers/) — Uploadcare provides media pipeline  with ultimate toolkit based on cutting-edge algorithms. All features are available for developers absolutely for free: File Uploading API and UI, Image CDN and Origin Services, Adaptive Delivery and Smart Compression.
   * [imagekit.io](https://imagekit.io) – Image CDN with automatic optimization, real-time transformation, and storage that you can integrate with existing setup in minutes. Free plan includes up to 20GB bandwidth per month.

## Design and UI

  * [Adobe XD](https://www.adobe.com/products/xd.html) - Wireframe & Prototyping tool similar to Sketch. Free plan covers: 1 active shared design spec, Adobe Fonts Free (limited set of fonts), 2GB of cloud storage.
  * [Mockplus iDoc](https://www.mockplus.com/idoc) - Mockplus iDoc is a powerful design collaboration & handoff tool. Free Plan includes 3 users and 5 projects with all features available.
  * [AllTheFreeStock](https://allthefreestock.com) - a curated list of free stock images, audio and videos.
  * [BoxySVG](https://boxy-svg.com/app) — A free installable Web app for drawing SVGs and exporting in svg,png,jpeg an other formats.
  * [clevebrush.com](https://www.cleverbrush.com/) — Free Graphics Design / Photo Collage App, also they offer paid integration of it as component.
  * [cloudconvert.com](https://cloudconvert.com/) — Convert anything to anything. 208 supported formats including videos to gif.
  * [CodeMyUI](https://codemyui.com) - Handpicked collection of Web Design & UI Inspiration with Code Snippets.
  * [designer.io](https://www.designer.io/) — Design tool for UI, illustrations and more. Has a native app. Free.
  * [figma.com](https://www.figma.com) — Online, collaborative design tool for teams; free tier includes unlimited files and viewers with a max of 2 editors and 3 projects.
  * [Icons8](https://icons8.com) — Icons, illustrations, photos, music, and design tools. Free Plan offers Limited formats in lower resolution. Link to Icons8 when you use our assets.
  * [imagebin.ca](https://imagebin.ca/) — Pastebin for images.
  * [Invision App](https://www.invisionapp.com) - UI design and prototyping tool. Desktop and webapp available. Free to use with 1 active prototype.
  * [landen.co](https://www.landen.co) — Generate, edit and publish beautiful websites and landing pages for your startup. All without code. Free tier allows you to have one website, fully customizable and published on the web.
  * [lensdump.com](https://lensdump.com/) - Free cloud image hosting.
  * [Lorem Picsum](https://picsum.photos/) - A Free tool, easy to use stylish placeholders. Just add your desired image size (width & height) after our URL, and you'll get a random image.
  * [marvelapp.com](https://marvelapp.com/) — Design, prototyping and collaboration, free plan limited to one user and one project.
  * [Mindmup.com](https://www.mindmup.com/) — Unlimited mind maps for free, and store them in the cloud. Your mind maps are available everywhere, instantly, from any device.
  * [mockupmark.com](https://mockupmark.com/create/free) — Create realistic t-shirt and clothing mockups for social media and E-commerce, 40 free mockups.
  * [Octopus.do](https://octopus.do) — Visual sitemap builder. Build your website structure in real-time and rapidly share it to collaborate with your team or clients.
  * [Pencil](https://github.com/evolus/pencil) - Open source design tool using Electron.
  * [Penpot](https://penpot.app) - Web based, open source design and prototyping tool. Supports SVG. Completely free.
  * [pexels.com](https://www.pexels.com/) - Free stock photos for commercial use. Has free API that allows you to search photos by keywords.
  * [photopea.com](https://www.photopea.com) — A Free, Advanced online design editor with Adobe Photoshop UI supporting PSD, XCF & Sketch formats (Adobe Photoshop, Gimp and Sketch App).
  * [pixlr.com](https://pixlr.com/) — Free online browser editor on the level of commercial ones.
  * [Plasmic](https://www.plasmic.app/) - A fast, easy to use, powerful web design tool and page builder that integrates into your codebase. Build responsive pages or complex components; optionally extend with code; and publish to production sites and apps.
  * [Proto.io](https://www.proto.io) - Create fully interactive UI prototypes without coding. Free tier available when free trial ends. Free tier includes: 1 user, 1 project, 5 prototypes, 100MB online storage and preview in proto.io app.
  * [resizeappicon.com](https://resizeappicon.com/) — A simple service to resize and manage your app icons.
  * [Rive](https://rive.app) — Create and ship beautiful animations to any platform. Free forever for Individuals. The service is a editor which hosts all the graphics on their servers as well. They also provide runtimes for many platforms to run graphics made using Rive.
  * [smartmockups.com](https://smartmockups.com/) — Create product mockups, 200 free mockups. 
  * [unDraw](https://undraw.co/) - A constantly updated collection of beautiful svg images that you can use completely free and without attribution.
  * [unsplash.com](https://unsplash.com/) - Free stock photos for commercial and noncommercial purposes (do-whatever-you-want license).
  * [vectr.com](https://vectr.com/) — Free Design App for Web + Desktop.
  * [walkme.com](https://www.walkme.com/) — Enterprise Class Guidance and Engagement Platform, free plan 3 walk-thrus up to 5 steps/walk.
  * [Webflow](https://webflow.com) - WYSIWYG web site builder with animations and website hosting. Free for 2 projects.
  * [Updrafts.app](https://updrafts.app) - WYSIWYG web site builder for tailwindcss based designs. Free for non-commercial usage.
  * [whimsical.com](https://whimsical.com/) - Collaborative flowcharts, wireframes, sticky notes and mind maps. Create up to 4 free boards.
  * [Zeplin](https://zeplin.io/) — Designer and developer collaboration platform. Show designs, assets and styleguides. Free for 1 project.
  * [Pixelixe](https://pixelixe.com/) — Create and edit engaging and unique graphics and images online.
  * [Responsively App](https://responsively.app) - A free dev-tool for faster and precise responsive web application development.
  * [SceneLab](https://scenelab.io) - Online mockup graphics editor with an ever-expanding collection of free design templates
  * [xLayers](https://xlayers.dev) - Preview and convert Sketch design files into Angular, React, Vue, LitElement, Stencil, Xamarin and more (free and open source at https://github.com/xlayers/xlayers)
  * [Grapedrop](https://grapedrop.com/) — Responsive, powerful, SEO optimized web page builder based on GrapesJS Framework. Free for first 5 pages, unlimited custom domains, all features and simple usage.

## Data Visualization on Maps

   * [IP Geolocation](https://ipgeolocation.io/) — Free DEVELOPER plan available with 30K requests/month.
   * [carto.com](https://carto.com/) — Create maps and geospatial APIs from your data and public data.
   * [datamaps.world](https://datamaps.world/) — The simple, yet powerful platform that gives you tools to visualize your geospatial data with a free tier.
   * [developers.arcgis.com](https://developers.arcgis.com) — APIs and SDKs for maps, geospatial data storage, analysis, geocoding, routing, and more across web, desktop, and mobile. 2,000,000 free basemap tiles, 20,000 non-stored geocodes, 20,000 simple routes, 5,000 drive time calculations, 5GB free tile+data storage per month.
   * [Foursquare](https://developer.foursquare.com/) - Location discovery, venue search, and context-aware content from Places API and Pilgrim SDK.
   * [geocod.io](https://www.geocod.io/) — Geocoding via API or CSV Upload. 2,500 free queries/day.
   * [geocodify.com](https://geocodify.com/) — Geocoding and Geoparsing via API or CSV Upload. 10k free queries/month.
   * [giscloud.com](https://www.giscloud.com/) — Visualize, analyze and share geo data online.
   * [gogeo.io](https://gogeo.io/) — Maps and geospatial services with an easy to use API and support for big data.
   * [graphhopper.com](https://www.graphhopper.com/) A free package for developers is offered for Routing, Route Optimization, Distance Matrix, Geocoding, Map Matching.
   * [here](https://developer.here.com/) — APIs and SDKs for maps and location-aware apps. 250k transactions/month for free.
   * [mapbox.com](https://www.mapbox.com/) — Maps, geospatial services and SDKs for displaying map data.
   * [maptiler.com](https://www.maptiler.com/cloud/) — Vector maps, map services and SDKs for map visualisation. Free vector tiles with weekly update and four map styles.
   * [opencagedata.com](https://opencagedata.com) — Geocoding API that aggregates OpenStreetMap and other open geo sources. 2,500 free queries/day.
   * [osmnames](https://osmnames.org/) — Geocoding, search results ranked by the popularity of related Wikipedia page.
   * [positionstack](https://positionstack.com/) - Free geocoding for global places and coordinates. 25.000 Requests per month for personal use.
   * [stadiamaps.com](https://stadiamaps.com/) — Map tiles, routing, navigation, and other geospatial APIs. 2,500 free map views and API requests / day for non-commercial usage and testing.
   * [http://maps.stamen.com/](http://maps.stamen.com/) - Free map tiles and tile hosting.
   * [GeocodeAPI](https://geocodeapi.io) - Geocode API: Address to Coordinate Conversion & Geoparsing based on Pelias. Batch geocoding via CSV. 350000 free requests/month.

## Package Build System

   * [build.opensuse.org](https://build.opensuse.org/) — Package build service for multiple distros (SUSE, EL, Fedora, Debian etc).
   * [copr.fedorainfracloud.org](https://copr.fedorainfracloud.org) — Mock-based RPM build service for Fedora and EL.
   * [help.launchpad.net](https://help.launchpad.net/Packaging) — Ubuntu and Debian build service.

## IDE and Code Editing

   * [3v4l](https://3v4l.org/) - Free online PHP shell and snippet sharing site, runs your code in 300+ PHP versions
   * [Android Studio](https://d.android.com/studio) — Android Studio provides the fastest tools for building apps on every type of Android device. Open Source IDE, free for everyone and the best to develop Android apps. Available for Windows,Mac,Linux and even ChromeOS!
   * [Apache Netbeans](https://netbeans.apache.org/) — Development Environment, Tooling Platform and Application Framework.
   * [apiary.io](https://apiary.io/) — Collaborative design API with instant API mock and generated documentation (Free for unlimited API blueprints and unlimited user with one admin account and hosted documentation).
   * [Atom](https://atom.io/) - Atom is a hackable text editor built on Electron.
   * [BlueJ](https://bluej.org) — A free Java Development Environment designed for beginners, used by millions worldwide. Powered by Oracle & simple GUI to help beginners.
   * [Bootify.io](https://bootify.io/) - Spring Boot app generator with custom database and REST API.
   * [cacher.io](https://www.cacher.io) — Code snippet organizer with labels and support for 100+ programming languages.
   * [Code::Blocks](https://codeblocks.org) — Free Fortran & C/C++ IDE. Open Source and runs on Windows,macOS & Linux.
   * [codesnip.com.br](https://codesnip.com.br) — Simple code snippets manager with categories, search and tags. free and unlimited.
   * [cocalc.com](https://cocalc.com/) — (formerly SageMathCloud at cloud.sagemath.com) — Collaborative calculation in the cloud. Browser access to full Ubuntu with built-in collaboration and lots of free software for mathematics, science, data science, preinstalled: Python, LaTeX, Jupyter Notebooks, SageMath, scikitlearn, etc.
   * [ide.cs50.io](https://ide.cs50.io/) - A free IDE powered by AWS Cloud9 by Harvard University.
   * [codepen.io](https://codepen.io/) — CodePen is a playground for the front end side of the web.
   * [codesandbox.io](https://codesandbox.io/) — Online Playground for React, Vue, Angular, Preact and more.
   * [Eclipse Che](https://www.eclipse.org/che/) - Web based and Kubernetes-Native IDE for Developer Teams with multi-language support. Open Source and community driven. A online instance hosted by Red Hat is available at [workspaces.openshift.com](https://workspaces.openshift.com/).
   * [fakejson.com](https://fakejson.com/) — FakeJSON helps you quickly generate fake data using its API. Make an API request describing what you want and how you want it. The API returns it all in JSON. Speed up the go to market process for ideas and fake it till you make it.
   * [gitpod.io](https://www.gitpod.io) — Instant, ready-to-code dev environments for GitHub projects. Free for open source.
   * [ide.goorm.io](https://ide.goorm.io) goormIDE is full IDE on cloud. multi-language support, linux-based container via the fully-featured web-based terminal, port forwarding, custom url, real-time collaboration and chat, share link, Git/Subversion support. There are many more features (free tier includes 1GB RAM and 10GB Storage per container, 5 Container slot).
   * [JDoodle](https://www.jdoodle.com) — Online compiler and editor for more than 60 programming languages with a free plan for REST API code compiling up to 200 credits per day.
   * [jetbrains.com](https://jetbrains.com/products.html) — Productivity tools, IDEs and deploy tools (aka [IntelliJ IDEA](https://www.jetbrains.com/idea/), [PyCharm](https://www.jetbrains.com/pycharm/), etc). Free license for students, teachers, Open Source and user groups.
   * [jsbin.com](https://jsbin.com) — JS Bin is another playground and code sharing site of front end web (HTML, CSS and JavaScript. Also supports Markdown, Jade and Sass).
   * [jsfiddle.net](https://jsfiddle.net/) — JS Fiddle is a playground and code sharing site of front end web, support collaboration as well.
   * [JSONPlaceholder](http://jsonplaceholder.typicode.com/) Some REST API endpoints that return some fake data in JSON format. The source code is also available if you would like to run the server locally.
   * [Katacoda](https://katacoda.com) — Interactive learning and training platform for software engineers helping developers learn and companies increase adoption.
   * [Lazarus](https://www.lazarus-ide.org/) — Lazarus is a Delphi compatible cross-platform IDE for Rapid Application Development.
   * [micro-jaymock](https://micro-jaymock.now.sh/) - Tiny API mocking microservice for generating fake JSON data.
   * [mockable.io](https://www.mockable.io/) — Mockable is a simple configurable service to mock out RESTful API or SOAP web-services. This online service allows you to quickly define REST API or SOAP endpoints and have them return JSON or XML data.
   * [mockaroo](https://mockaroo.com/) — Mockaroo lets you generate realistic test data in CSV, JSON, SQL, and Excel formats. You can also create mocks for back-end API.
   * [Mocklets](https://mocklets.com) - a HTTP-based mock API simulator, which helps simulate APIs for faster parallel development and more comprehensive testing, with lifetime free tier.
   * [Prepros](https://prepros.io/) - Prepros can compile Sass, Less, Stylus, Pug/Jade, Haml, Slim, CoffeeScript and TypeScript out of the box, reloads your browsers and makes it really easy to develop & test your websites so you can focus on making them perfect. You can also add your own tools with just a few clicks.
   * [repl.it](https://repl.it/) — A cloud coding environment for various program languages.
   * [SoloLearn](https://code.sololearn.com) — A cloud programming playground well-suited for running code snippets. Supports various programming languages. No registration required for running code but required when you need to save code on their platform. Also offers free courses for begginers and intermediate level coders.
   * [stackblitz.com](https://stackblitz.com/) — Online VS Code IDE for Angular & React.
   * [Visual Studio Code](https://code.visualstudio.com/) - Code editor redefined and optimized for building and debugging modern web and cloud applications. Developed by Microsoft for Windows, macOS and Linux.
   * [Visual Studio Community](https://visualstudio.microsoft.com/vs/community/) — Fully-featured IDE with thousands of extensions, cross-platform app development (Microsoft extensions available for download for iOS and Android), desktop, web and cloud development, multi-language support (C#, C++, JavaScript, Python, PHP and more).
   * [VSCodium](https://vscodium.com/) - Community-driven, without telemetry/tracking, and freely-licensed binary distribution of Microsoft’s editor VSCode
   * [wakatime.com](https://wakatime.com/) — Quantified self-metrics about your coding activity, using text editor plugins, limited plan for free.

## Analytics, Events and Statistics

   * [AO Analytics](https://analytics.ao.gl/) — Forever FREE Customer Analytics for ALL your websites, with Unlimited Events per month
   * [Avo](https://avo.app/) — Simplified analytics release workflow. Single-source-of-truth tracking plan, type safe analytics tracking library, in-app debuggers, data observability to catch all data issues before you release. Free for 2 workspace members and 1 hour data observability lookback.
   * [Branch](https://branch.io) — Mobile Analytics Platform. Free Tier offers upto 10K Mobile App Users with deep-linking & other services.
   * [Clicky](https://clicky.com) — Website Analytics Platform. Free Plan for 1 website with 3000 views analytics.
   * [indicative.com](https://indicative.com/) — Customer analytics platform to optimize customer engagement, increase conversion, and improve retention. Free up to 50M events/month.
   * [Panelbear.com](https://panelbear.com/) — Blazingly fast and private, free tier includes 5,000 pageviews per month for unlimited websites
   * [Hitsteps.com](https://hitsteps.com/) — 2,000 pageviews per month for 1 website
   * [amplitude.com](https://amplitude.com/) — 1 million monthly events, up to 2 apps
   * [goatcounter.com](https://www.goatcounter.com/) — GoatCounter is an open source web analytics platform available as a hosted service (free for non-commercial use) or self-hosted app. It aims to offer easy to use and meaningful privacy-friendly web analytics as an alternative to Google Analytics or Matomo. Free tier is for non-commerical use and includes unlimited number of sites, 6 months of data retention, and 100k pageviews/month.
   * [Google Analytics](https://analytics.google.com/) — Google Analytics
   * [expensify.com](https://www.expensify.com/) — Expense reporting, free personal reporting approval workflow
   * [getinsights.io](https://getinsights.io) - Privacy-focused, cookie free analytics, free for up to 5k events/month.
   * [heap.io](https://heap.io) — Automatically captures every user action in iOS or web apps. Free for up to 5,000 visits/month
   * [Hotjar](https://hotjar.com) — Website Analytics and Reports . Free Plan allows 2000 pageviews/day. 100 snapshots/day (max capacity: 300). 3 snapshot heatmaps which can be stored for 365 days. Unlimited Team Members.
   * [imprace.com](https://imprace.com/) — Landing page analysis with suggestions to improve bounce rates. Free 5 landing pages/domain
   * [keen.io](https://keen.io/) — Custom Analytics for data collection, analysis and visualization. 50,000 events/month free
   * [metrica.yandex.com](https://metrica.yandex.com/) — Unlimited free analytics
   * [mixpanel.com](https://mixpanel.com/) — 100,000 monthly tracked users, unlimited data history and seats, US or EU data residency
   * [Moesif](https://www.moesif.com) — API analytics for REST and GraphQL. (Free up to 500,000 API calls/mo)
   * [Molasses](https://www.molasses.app) - Powerful feature flags and A/B testing. Free up to 3 environments with 5 feature flags each.
   * [optimizely.com](https://www.optimizely.com) — A/B Testing solution, free starter plan, 1 website, 1 iOS and 1 Android app
   * [Microsoft PowerBI](https://powerbi.com) — Business Insights & Analytics by Microsoft. Free Plan offers limited use with 1 Million User licenses.
   * [quantcast.com](https://www.quantcast.com/products/measure-audience-insights/) — Unlimited free analytics
   * [sematext.com](https://sematext.com/cloud/) — Free for up to 50 K actions/month, 1-day data retention, unlimited dashboards, users, etc.
   * [Similar Web](https://similarweb.com) — Analytics for Web & Mobile Apps. Free Plan offers 5 results per metric, 1 month of mobile app data & 3 months of website data.
   * [StatCounter](https://statcounter.com/) — Website Viewer Analytics. Free plan for analytics of 500 most recent visitors.
   * [Tableau Developer Program](https://www.tableau.com/developer) — Innovate, create, and make Tableau work perfectly for your organization. Free developer program gives a personal development sandbox license for Tableau Online. The version is the latest pre-release version so Data Devs can test each & every feature of this superb platform.
   * [usabilityhub.com](https://usabilityhub.com/) — Test designs and mockups on real people, track visitors. Free for one user, unlimited tests
   * [woopra.com](https://www.woopra.com/) — Free user analytics platform for 500K actions, 90 day data retention, 30+ one click integration.

## Visitor Session Recording

   * [Reactflow.com](https://www.reactflow.com/) — Per site: 1,000 pages views/day, 3 heatmaps, 3 widgets, free bug tracking
   * [LogRocket.com](https://www.logrocket.com) - 1,000 sessions/month with 30 day retention, error tracking, live mode
   * [FullStory.com](https://www.fullstory.com) — 1,000 sessions/month with 1 month data retention and 3 user seats. More information [here](https://help.fullstory.com/hc/en-us/articles/360020623354-FullStory-Free-Edition).
   * [hotjar.com](https://www.hotjar.com/) — Per site: 2,000 pages views/day, 3 heatmaps, data stored for 3 months,...
   * [inspectlet.com](https://www.inspectlet.com/) — 100 sessions/month free for 1 website
   * [livesession.io](https://livesession.io/) — 1,000 sessions/month free for 1 website
   * [mouseflow.com](https://mouseflow.com/) — 100 sessions/month free for 1 website
   * [mousestats.com](https://www.mousestats.com/) — 100 sessions/month free for 1 website
   * [smartlook.com](https://www.smartlook.com/) — free packages for web and mobile apps (1500 sessions/month), 3 heatmaps, 1 funnel, 1-month data history
   * [usersurge.com](https://www.usersurge.com/) — 250K sessions per month for individuals.
   * [howuku.com](https://howuku.com) — Track user interaction, engagement, and event. Free for up to 5,000 visits/month

## International Mobile Number Verification API and SDK

  * [cognalys.com](https://cognalys.com/) — Freemium mobile number verification through an innovative and reliable method than using SMS gateway. Free 10 tries and 15 verifications/day
  * [numverify.com](https://numverify.com/) — Global phone number validation and lookup JSON API. 250 API requests/month
  * [veriphone.io](https://veriphone.io/) — Global phone number verification in a free, fast, reliable JSON API. 1000 requests/month

## Payment and Billing Integration

  * [CurrencyFreaks](https://currencyfreaks.com/) — Provides current and historical currency exchange rates. Free DEVELOPER plan available with 1000 requests/month.
  * [currencyapi.net](https://currencyapi.net/) — Live Currency Rates for Physical and Crypto currencies, delivered in JSON and XML. Free tier offers 1,250 API requests/month.
  * [currencylayer.com](https://currencylayer.com/) — Reliable Exchange Rates and Currency Conversion for your Business, 1,000 API requests/month free
  * [currencystack.io](https://currencystack.io/) — Production-ready real-time exchange rates for 154 currencies.
  * [exchangerate-api.com](https://www.exchangerate-api.com) - An easy to use currency conversion JSON API. Free tier with no request limit.
  * [fraudlabspro.com](https://www.fraudlabspro.com) — Help merchants to prevent payment fraud and chargebacks. Free Micro Plan available with 500 queries/month.
  * [mailpop.in](https://mailpop.in) - Get the most of your Stripe notifications with contextualized information.
  * [namiml.com](https://www.namiml.com/) - Complete platform for in-app purchases and subscriptions on iOS and Android, including no-code paywalls, CRM, and analytics.  Free for all base features to run an IAP business.
  * [revenuecat.com](https://www.revenuecat.com/) — Hosted backend for in-app purchases and subscriptions (iOS and Android). Free up to $10k/mo in tracked revenue.
  * [vatlayer.com](https://vatlayer.com/) — Instant VAT number validation and EU VAT rates API, free 100 API requests/month
  * [freecurrencyapi.net](https://freecurrencyapi.net/) — Free currency conversion and exchange rate data API. 10 requests/hour without an API key, 50 000 requests per month when you register for free.

## Docker Related

  * [canister.io](https://canister.io/) — 20 free private repositories for developers, 30 free private repositories for teams to build and store Docker images
  * [Container Registry Service](https://container-registry.com/) - Harbor based Container Management Solution. Free tier offers 1 GB storage for private repositories.
  * [Docker Hub](https://hub.docker.com) — One free private repository and unlimited public repositories to build and store Docker images
  * [Play with Docker](https://labs.play-with-docker.com/) — A simple, interactive and fun playground to learn Docker.
  * [quay.io](https://quay.io/) — Build and store container images with unlimited free public repositories
  * [TreeScale.com](https://treescale.com/) — Host and manage container images with group permissions. Free tier offers 1 GB storage for private repositories.

## Vagrant Related

  * [app.vagrantup.com](https://app.vagrantup.com) - HashiCorp Vagrant Cloud. Vagrant box hosting.
  * [vagrantbox.es](https://www.vagrantbox.es/) — An alternative public box index

## Dev Blogging Sites

  * [dev.to](https://dev.to/) - Where programmers share ideas and help each other grow.
  * [hashnode.com](https://hashnode.com/) — Hassle-free Blogging Software for Developers!.
  * [medium.com](https://medium.com/) — Get smarter about what matters to you.

## Commenting Platforms
  * [Staticman](https://staticman.net/) - Staticman is a Node.js application that receives user-generated content and uploads it as data files to a GitHub and/or GitLab repository, using Pull Requests.
  * [GraphComment](https://graphcomment.com/) - GraphComment is a comments platform that helps you build an active community from website’s audience.
  * [Utterances](https://utteranc.es/) - A lightweight comments widget built on GitHub issues. Use GitHub issues for blog comments, wiki pages and more!
  * [Disqus](https://disqus.com/) - Disqus is a networked community platform used by hundreds of thousands of sites all over the web.


## Screenshot APIs

  * [24browser.com](https://www.24browser.com) – Capture beautifully rendered website screenshots at scale with powerful API.
  * [ApiFlash](https://apiflash.com) — A screenshot API based on Aws Lambda and Chrome. Handles full page, capture timing, viewport dimensions, ...
  * [microlink.io](https://microlink.io/) – It turns any website into data such as metatags normalization, beauty link previews, scraping capabilities or screenshots as a service. 250 reqs/day every day free.
  * [ScreenshotAPI.net](https://screenshotapi.net/) - Screenshot API use one simple API call to generate screenshots of any website. Build to scale and hosted on Google Cloud. Offers 100 free screenshots per month.
  * [screenshotlayer.com](https://screenshotlayer.com/) — Capture highly customizable snapshots of any website. Free 100 snapshots/month
  * [screenshotmachine.com](https://www.screenshotmachine.com/) — Capture 100 snapshots/month, png, gif and jpg, including full-length captures, not only home page
  * [PhantomJsCloud](https://PhantomJsCloud.com) — Browser automation and page rendering.  Free Tier offers up to 500 pages/day.  Free Tier since 2017.
  * [Webshrinker.com](https://webshrinker.com) — Web Shrinker provides web site screenshot and domain intelligence API services. Free 100 requests/month.

## Browser based hardware emulation written in Javascript

  * [JsLinux](https://bellard.org/jslinux) — a really fast x86 virtual machine capable of running Linux and Windows 2k.
  * [Jor1k](http://s-macke.github.io/jor1k/demos/main.html) —  a OpenRISC virtual machine capable of running Linux with network support.
  * [v86](https://copy.sh/v86) — a x86 virtual machine capable of running Linux and other OS directly into the browser.

## Miscellaneous

  * [Smartcar API](https://smartcar.com) - An API for cars to locate, get fuel tank, battery levels, odometer, unlock/lock doors, etc.
  * [Blynk](https://blynk.io) — A SaaS with API to control, build & evaluate IoT devices. Free Developer Plan with 5 devices,Free Cloud & data storage. Mobile Apps also available.
  * [Bricks Note Calculator](https://free.getbricks.app/) - a note-taking app (PWA) with a powerful built-in multiline calculator.
  * [Code Time](https://www.software.com/code-time) - an extension for time-tracking and coding metrics in VS Code, Atom, IntelliJ, Sublime Text, and more.
  * [ConfigCat](https://configcat.com) - Cross-platform feature flag service. SDKs for all major languages. Free plan up to 10 flags, 2 environments, 1 product and 5 Million requests per month. Unlimited user seats. Students get 100 flags and 100 Million requests per month for free.
  * [datelist.io](https://datelist.io) - Online booking / appointment scheduling system. Free up to 5 bookings per month, includes 1 calendar
  * [docsapp.io](https://www.docsapp.io/) — Easiest way to publish documentation, free for Open Source
  * [Elementor](https://elementor.com) — WordPress website builder. Free plan available with 40+ Basic Widgets.
  * [Form2Channel](https://form2channel.com) — Place a static html form on your website and receive submissions directly to Google Sheets, Email, Slack, Telegram or Http. No coding necessary.
  * [FOSSA](https://fossa.com/) - Scalable, end-to-end management for third-party code, license compliance and vulnerabilities.
  * [fullcontact.com](https://www.fullcontact.com/developer/pricing/) — Help your users know more about their contacts by adding social profile into your app. 500 free Person API matches/month
  * [http2.pro](https://http2.pro) — HTTP/2 protocol readiness test and client HTTP/2 support detection API.
  * [JWT Decoder](https://jwt.ssotools.com/) — Online free tool for decoding JWT(JSON web token) and verifying it's signature.
  * [Base64 decoder/encoder](https://devpal.xyz/base64-decode/) — Online free tool for decoding & encoding data.
  * [newreleases.io](https://newreleases.io/) - Receive notifications on email, Slack, Telegram, Discord and custom webhooks for new releases from GitHub, GitLab, Bitbucket, Python PyPI, Java Maven, Node.js NPM, Node.js Yarn, Ruby Gems, PHP Packagist, .NET NuGet, Rust Cargo and Docker Hub.
  * [PDFMonkey](https://www.pdfmonkey.io/) — Manage PDF templates in a dashboard, call the API with dynamic data, download your PDF. Offers 1000 free documents per month.
  * [readme.com](https://readme.com/) — Beautiful documentation made easy, free for Open Source.
  * [redirection.io](https://redirection.io/) — SaaS tool for managing HTTP redirections for businesses, marketing and SEO.
  * [ReqBin](https://www.reqbin.com/) — Post HTTP Requests Online. Popular Request Methods include GET, POST, PUT, DELETE, and HEAD. Supports Headers and Token Authentication. Includes a basic login system for saving your requests.
  * [superfeedr.com](https://superfeedr.com/) — Real-time PubSubHubbub compliant feeds, export, analytics. Free with less customization
  * [SurveyMonkey.com](https://www.surveymonkey.com) — Create online surveys. Analyze the results online.  Free plan allows only 10 questions and 100 responses per survey.
  * [videoinu](https://videoinu.com) — Create and edit screen recordings and other videos online.
  * [RandomKeygen](https://randomkeygen.com/) - A free mobile-friendly tool offers a variety of randomly generated keys and passwords you can use to secure any application, service or device.
  * [Cronhooks](https://cronhooks.io/) - Schedule one time or recurring webhooks using api and web app. Free plan allows 1 webhook schedule.
  * [Hook Relay](https://www.hookrelay.dev/) - Add webhook support to your app without the hassles: done-for-you queueing, retries with backoff, and logging. The free plan has 100 deliveries per day, 14-day retention, and 3 hook endpoints.

## Other Free Resources

  * [education.github.com](https://education.github.com/pack) — Collection of free services for students. Registration required
  * [Framacloud](https://degooglisons-internet.org/en/list/) — A list of Free/Libre Open Source Software and SaaS by the French non-profit [Framasoft](https://framasoft.org/en/).
  * [getawesomeness](https://getawesomeness.herokuapp.com) — Retrieve all amazing awesomeness from GitHub... a must see
  * [github.com — FOSS for Dev](https://github.com/tvvocold/FOSS-for-Dev) — A hub of free and Open Source software for developers.
  * [Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program) — Get a free sandbox, tools, and other resources you need to build solutions for the Microsoft 365 platform. The subscription is a 90-day [Microsoft 365 E5 Subscription](https://www.microsoft.com/microsoft-365/enterprise/e5) (Windows excluded) which is renewable. It is renewed if you're active in development(measured using telemetry data & algorithms).
  * [RedHat for Developers](https://developers.redhat.com) — Free access to Red Hat products including RHEL,OpenShift,CodeReady etc exclusively for developers. Individual plan only. Free e-Books also offered for reference.
  * [smsreceivefree.com](https://smsreceivefree.com/) — Provides free temporary and disposable phone numbers.
  * [simplebackups.io](https://simplebackups.io/) — Backup automation service for servers and databases (MySQL, PostgreSQL, MongoDB) stored directly into cloud storage providers (AWS, DigitalOcean, Backblaze...). Provides free plan for 1 backup.
  * [SnapShooter](https://snapshooter.com/) — Backup solution for DigitalOcean, AWS, LightSail, Hetzner and Exoscale, with support for direct database, file system and application backups to s3 based storage. Provides a free plan with daily backups for one resource.
  * [Web.Dev](https://web.dev/measure/) — This is a free tool that allows you to see the performance of your website and improve the SEO to get higher rank list in search engines.
