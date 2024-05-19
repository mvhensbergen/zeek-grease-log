FROM zeek/zeek:latest

RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    g++ \
    libpcap-dev \
    make \
    npm \
    vim \
    wget

# Copy the source dir
COPY . /usr/local/zeek/share/zeek/site

RUN echo "@load ./grease.zeek" >> /usr/local/zeek/share/zeek/site/local.zeek

# Download the PCAP file from the Zeek GitHub link
RUN mkdir -p /home/firefox
RUN wget -q https://github.com/zeek/zeek/raw/1a0fffd714bf1e3523778cf616513294a5b71f9c/testing/btest/Traces/quic/firefox-102.13.0esr-blog-cloudflare-com.pcap \
    -O /home/firefox/firefox-102.13.0esr-blog-cloudflare-com.pcap

# Download the PCAP file from the Zeek GitHub link
RUN mkdir -p /home/chrome
RUN wget -q https://github.com/zeek/zeek/raw/1a0fffd714bf1e3523778cf616513294a5b71f9c/testing/btest/Traces/quic/chromium-115.0.5790.110-google-de-fragmented.pcap \
    -O /home/chrome/chromium-115.0.5790.110-google-de-fragmented.pcap

WORKDIR /home/firefox
RUN zeek -Cr /home/firefox/firefox-102.13.0esr-blog-cloudflare-com.pcap /usr/local/zeek/share/zeek/site/grease.zeek

WORKDIR /home/chrome
RUN zeek -Cr /home/chrome/chromium-115.0.5790.110-google-de-fragmented.pcap /usr/local/zeek/share/zeek/site/grease.zeek