module StackWatch
  module Sources
    class OSV
      BASE_URI    = URI('https://api.osv.dev/v1/querybatch')
      TIMEOUT_SEC = 15

      def initialize(packages)
        @packages = packages
      end

      def fetch_all
        return {} if @packages.empty?

        body = post_batch(build_payload)
        parse_response(body)
      end

      private

      def build_payload
        queries = @packages.map do |pkg|
          { 'package' => { 'name' => pkg.name, 'ecosystem' => pkg.ecosystem } }
        end
        { 'queries' => queries }
      end

      def post_batch(payload)
        http = Net::HTTP.new(BASE_URI.host, BASE_URI.port)
        http.use_ssl      = true
        http.open_timeout = TIMEOUT_SEC
        http.read_timeout = TIMEOUT_SEC

        req = Net::HTTP::Post.new(BASE_URI.path)
        req['Content-Type'] = 'application/json'
        req.body = JSON.generate(payload)

        res = http.request(req)
        raise OSVError, "OSV API error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)

        JSON.parse(res.body)
      rescue Net::OpenTimeout, Net::ReadTimeout => e
        raise OSVError, "OSV API timeout: #{e.message}"
      rescue JSON::ParserError => e
        raise OSVError, "OSV API returned invalid JSON: #{e.message}"
      end

      def parse_response(body)
        results = body.fetch('results', [])
        @packages.zip(results).each_with_object({}) do |(pkg, result), map|
          vulns = result&.fetch('vulns', []) || []
          map[pkg] = vulns.map { |v| Vuln.from_osv(v) }
        end
      end
    end
  end
end
