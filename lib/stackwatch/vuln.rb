module StackWatch
  Vuln = Struct.new(:id, :summary, :cvss_score, :affected, :fixed, :url,
                    :published, :withdrawn, keyword_init: true) do
    def withdrawn?
      !withdrawn.nil?
    end

    def older_than?(cutoff)
      return false if published.nil?

      published < cutoff
    end

    class << self
      def from_osv(raw)
        id = raw['id']
        new(
          id: id,
          summary: extract_summary(raw),
          cvss_score: extract_cvss(raw),
          affected: extract_affected(raw),
          fixed: extract_fixed(raw),
          url: "https://osv.dev/vulnerability/#{id}",
          published: parse_time(raw['published']),
          withdrawn: parse_time(raw['withdrawn'])
        )
      end

      private

      def extract_summary(raw)
        (raw['summary'] || raw['details'].to_s.slice(0, 200)).to_s.strip
      end

      def extract_cvss(raw)
        raw.dig('severity')
           &.find { |s| s['type'] == 'CVSS_V3' }
           &.dig('score') ||
          raw.dig('database_specific', 'cvss', 'score') ||
          'N/A'
      end

      def extract_affected(raw)
        events = raw.dig('affected', 0, 'ranges', 0, 'events') || []
        introduced = events.select { |e| e['introduced'] }.map { |e| ">=#{e['introduced']}" }
        introduced.empty? ? 'unknown' : introduced.join(', ')
      end

      def extract_fixed(raw)
        events = raw.dig('affected', 0, 'ranges', 0, 'events') || []
        events.find { |e| e['fixed'] }&.dig('fixed')
      end

      def parse_time(value)
        return nil if value.nil? || value.to_s.strip.empty?

        Time.iso8601(value.to_s)
      rescue ArgumentError
        nil
      end
    end
  end
end
