# frozen_string_literal: true

module Kantan
  module H2
    module Body
      class Buffer
        def initialize string
          @string = string
          @offset = 0
        end

        def read n
          chunk = @string.byteslice(@offset, n)
          @offset += n
          chunk
        end

        def bytesize
          @string.bytesize - @offset
        end

        def empty?
          @offset >= @string.bytesize
        end

        def close
        end
      end

      class File
        def initialize path
          @io = ::File.open(path, "rb")
          @remaining = @io.size
        end

        def read n
          chunk = @io.read(n)
          @remaining -= chunk.bytesize
          chunk
        end

        def bytesize
          @remaining
        end

        def empty?
          @remaining == 0
        end

        def close
          @io.close
        end
      end
    end
  end
end
