
# Referer Graph

Visualize the directed graph of HTTP "Referer" headers.

## How to Install

Referer Graph is comprised of 3 parts that work together sequentially:

1. Burp Suite extension
2. Node.js server
3. Web application

### Prerequisites:
```
Node14, Java11, Gradle6.9
```

Gradle version 6.9 is specifically needed; the gradle build file won't work with version 7 and some earlier versions.

"sdkman" is a convenient way to install specific Java and Gradle versions. On Windows, you can use WSL to use sdkman.

### Node.js server
```
npm install && \
npm run build-all
```

### Burp extension .jar

Navigate to the `burp/` directory and run:
```
gradle shadowJar
```

`burp/libs/burp-extension-web-app-flow-visualizer-all.jar` is created if successful.

## How to Use

Use the following steps to get everything up and running:

1. Complete installation as described in `How to Install`
2. In the base directory, run `npm start` to start the Node.js server
3. Import the `burp-extension-web-app-flow-visualizer-all.jar` in the `burp/libs/` directory to Burp Extender
4. In the "Referer Graph" tab in Burp Suite, setup the configuration to your use case.
5. Navigate to `http://localhost:8000` to access the visualization web-app (assuming you are running the server with default port on localhost)
