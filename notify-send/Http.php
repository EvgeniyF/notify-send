<?php
/**
 * HSDN SME
 *
 * Site Management Engine
 *
 * @package		ELISA
 * @author		HSDN Team
 * @copyright	Copyright (c) 2009-2011, Information Networks Ltd.
 * @link		http://www.hsdn.org
 * @since		Version 2
 */

// ------------------------------------------------------------------------

/**
 * Класс Http
 *
 * @package		LRG
 * @category	Libraries
 * @author		HSDN Team
 * @version		1.1.17
 */
class Http
{
	/*
	 * Инстанция класса Socket
	 *
	 * @access	private
	 */
	private $socket;

	/*
	 * Режим отладки
	 *
	 * @access	private
	 */
	private $debug;

	/*
	 * Номер ошибки соединения
	 *
	 * @access	private
	 */
	public $errno = NULL;

	/*
	 * Строка ошибки соединения
	 *
	 * @access	private
	 */
	public $errstr = NULL;


	/**
	 * Конструктор
	 *
	 * @access	public
	 * @param	bool
	 * @return	void
	 */
	public function __construct($debug = FALSE)
	{
		$this->debug = $debug;

		$this->socket = new Socket(FALSE);
	}

	/**
	 * Открытие соединения
	 *
	 * @access	public
	 * @param	string
	 * @param	int
	 * @param	string
	 * @return	mixed
	 */
	public function open($host, $port = 80, $use_ssl = FALSE, $timeout = 10, $ssl_type = STREAM_CRYPTO_METHOD_SSLv23_CLIENT)
	{
		$socket = $this->socket->open($host, $port, $timeout);

		$this->errno = $this->socket->errno;
		$this->errstr = $this->socket->errstr;

		if ($this->socket->enable_crypto($socket, $use_ssl, $ssl_type) !== TRUE)
		{
			return FALSE;
		}

		return $socket;
	}

	/**
	 * Открытие соединения через proxy
	 *
	 * @access	public
	 * @param	string
	 * @param	int
	 * @param	string
	 * @return	mixed
	 */
	public function open_proxy($proxy_host, $proxy_port, $host, $port, $proxy_login = FALSE, $proxy_password = FALSE, $proxy_type = 'HTTP', $timeout = 10)
	{
		$socket = $this->socket->open_proxy($proxy_host, $proxy_port, $host, $port, $proxy_login, $proxy_password, $proxy_type, $timeout);

		$this->errno = $this->socket->errno;
		$this->errstr = $this->socket->errstr;

		return $socket;
	}

	/**
	 * Блокировка потока
	 *
	 * @access	public
	 * @param	resource
	 * @param	bool
	 * @return	bool
	 */
	public function set_blocking(&$socket, $blocking)
	{
		if(!is_resource($socket)) 
		{
			return FALSE;
		}

		return $this->socket->set_blocking($socket, $blocking);
	}

	/**
	 * Установка времени ожидания данных из потока
	 *
	 * @access	public
	 * @param	resource
	 * @param	bool
	 * @return	bool
	 */
	public function set_timeout(&$socket, $seconds, $microseconds = 0)
	{
		if(!is_resource($socket)) 
		{
			return FALSE;
		}

		return $this->socket->set_timeout($socket, $seconds, $microseconds = 0);
	}

	/**
	 * Чтение HTTP контента
	 *
	 * @access	public
	 * @param	resource
	 * @return	bool
	 */
	public function get_content(&$socket)
	{
		if(!is_resource($socket)) 
		{
			return FALSE;
		}

		if (!$head = $this->read_head($socket))
		{
			return FALSE;
		}

		$code = $this->parse_status_code($head);
		$headers = $this->parse_headers($head);
		$body = $this->read($socket);

		return array
		(
			'code' => $code,
			'headers' => $headers,
			'body' => $body
		);
	}

	/**
	 * Чтение заголовков HTTP из потока
	 *
	 * @access	public
	 * @param	resource
	 * @return	string
	 */
	public function read_head(&$socket)
	{
		if(!is_resource($socket)) 
		{
			return FALSE;
		}

		$read = '';

		while (($line = $this->read_line($socket)) !== FALSE)
		{
			$read .= $line;
		}

		return ($read == '') ? FALSE : $read;
	}

	/**
	 * Чтение тела HTTP из потока
	 *
	 * @access	public
	 * @param	resource
	 * @return	string
	 */
	public function read_body(&$socket)
	{
		if(!is_resource($socket)) 
		{
			return FALSE;
		}

		$this->read_head($socket);

		return $this->read($socket);
	}

	/**
	 * Чтение данных из потока
	 *
	 * @access	public
	 * @param	resource
	 * @return	bool
	 */
	public function read(&$socket) 
	{ 
        if(!is_resource($socket))  
        { 
            return FALSE; 
        }

        $read = ''; 

        if ($this->debug) 
        { 
            echo 'BEGIN RECEIVING --> '; 
			flush();
        } 

		$d = 0;

        while (TRUE)  
        {
			$read .= $s = $this->socket->read($socket, 65535); 
			$socet_status = $this->socket->get_meta_data($socket);

			if ($socet_status['timed_out'] != FALSE OR $socet_status['eof'] == TRUE)
			{
				break;
			}

            if ($this->debug AND $d >= 1024)
            {
				$d = 0;
				echo ($s == '') ? '*' : '|';
				flush();
            }

			$d++;
        } 

        if ($this->debug) 
        { 
            echo " <-- RECEIVING END\n"; 
			flush();
        } 

        return $read; 
    } 

	/**
	 * Запись данных в поток
	 *
	 * @access	public
	 * @param	resource
	 * @param	string
	 * @return	bool
	 */
	public function write(&$socket, $request)
	{
		if(!is_resource($socket)) 
		{
			return FALSE;
		}

		return $this->socket->write($socket, $request);
	}

	/**
	 * Чтение строки данных из потока
	 *
	 * @access	public
	 * @param	resource
	 * @return	bool
	 */
	public function read_line(&$socket)
	{
		$read = '';
       
		while (($character = $this->socket->read($socket, 1)) != "\n")
        {
			$socet_status = $this->socket->get_meta_data($socket);
			$read .= $character;

			if ($socet_status['timed_out'] != FALSE OR $socet_status['eof'] == TRUE)
			{
				break;
			}
        }

		// trim, trim, trim...
		return (trim($read) == '') ? FALSE : $read;
	}

	/**
	 * Закрытие потока
	 *
	 * @access	public
	 * @param	resource
	 * @return	void
	 */
	public function close($socket)
	{
		if(is_resource($socket)) 
		{
			return $this->socket->close($socket);
		}
	}

	/**
	 * Проверка контента на правильность
	 *
	 * @access	public
	 * @param	array
	 * @param	bool
	 * @return	bool
	 */
	public function validate_content($content, $valid_code = FALSE)
	{
		if (!isset($content['code']) 
			OR !isset($content['headers']) 
			OR !isset($content['body']))
		{
			return FALSE;
		}

		if ($valid_code !== FALSE AND $valid_code != $content['code'])
		{
			return FALSE;
		}

		if (isset($content['headers']['Content-Length']) 
			AND (int) $content['headers']['Content-Length'] !== strlen($content['body']))
		{
			return FALSE;
		}

		return TRUE;
	}

	/**
	 * Декодирование контента
	 *
	 * @access	public
	 * @param	array
	 * @return	array
	 */
	public function decode_content($content)
	{
		if (isset($content['headers']['Content-Encoding']))
		{
			switch ($content['headers']['Content-Encoding'])
			{
				case 'gzip':
					$content['body'] = gzdecode($content['body'], strlen($content['body']));
					break;

				case 'deflate':
					$content['body'] = gzinflate($content['body']);
					break;
			}
		}

		return $content;
	}

	/**
	 * Генерация HTTP запроса
	 *
	 * @access	public
	 * @param	string
	 * @param	string
	 * @param	array
	 * @param	string
	 * @return	string
	 */
	public function generate_request($method, $path, $headers = array(), $body = '', $http_version = '1.0')
	{
		$request = strtoupper($method).' '.$path.' HTTP/'.$http_version."\r\n";
		$request .= $this->generate_headers($headers);

		if ($body != '')
		{
			 $request .= $body."\r\n";
		}

		return $request;
	}

	/**
	 * Генерация HTTP заголовков
	 *
	 * @access	public
	 * @param	array
	 * @return	string
	 */
	public function generate_headers($headers)
	{
		if (sizeof($headers) == 0)
		{
			return '';
		}

		$headers_string = '';

		foreach ($headers as $name => $value)
		{
			if ($name != '' AND $value != '')
			{
				if (is_array($value))
				{
					$sub_headers = '';

					foreach ($value as $sub_value)
					{
						$sub_headers .= $sub_value.';';
					}

					$headers_string .= $name.': '.trim($sub_headers, ';')."\r\n";
				}
				else
				{
					$headers_string .= $name.': '.$value."\r\n";
				}
			}
		}

		return $headers_string."\r\n";
	}

	/**
	 * Генерация URI строки
	 *
	 * @access	public
	 * @param	array
	 * @return	string
	 */
	public function generate_uri($uri)
	{
		if (sizeof($uri) == 0)
		{
			return '';
		}

		$uri_string = '';

		foreach ($uri as $name => $value)
		{
			if ($name != '')
			{
				$uri_string .= $name.'='.urlencode($value).'&';
			}
		}

		return trim($uri_string, '&');
	}

	/**
	 * Парсинг HTTP заголовков
	 *
	 * @access	public
	 * @param	string
	 * @return	array
	 */
	public function parse_headers($headers)
	{
		$lines = explode("\n", str_replace(array("\r\n", "\r"), "\n", $headers));

		$headers = array();

		if (sizeof($lines) > 0)
		{
			foreach ($lines as $line)
			{
				$header = explode(': ', $line);

				if (isset($header[0]) AND isset($header[1]))
				{
					if (isset($headers[$header[0]]) AND !is_array($headers[$header[0]]))
					{
						$headers[$header[0]] = array($headers[$header[0]]);
					}

					if (isset($headers[$header[0]]) AND is_array($headers[$header[0]]))
					{
						$headers[$header[0]][] = trim($header[1]);
					}
					else
					{
						$headers[$header[0]] = trim($header[1]);
					}
				}
			}
		}

		return $headers;
	}

	/**
	 * Парсинг кода HTTP ответа
	 *
	 * @access	public
	 * @param	string
	 * @return	int
	 */
	public function parse_status_code($headers)
	{
		if (strlen($headers) < 12)
		{
			return FALSE;
		}

		$status = substr($headers, 9, 3);

		if (!is_numeric($status))
		{
			return FALSE;
		}

		return $status;
	}

} // End of class Http

if (!function_exists('gzdecode'))
{
	/**
	 * Декодировать сжатую GZip строку
	 *
	 * @access	public
	 * @param	string
	 * @param	int
	 * @return	array
	 */
	function gzdecode($data, $len = FALSE) 
	{
		$len = ($len === FALSE) ? strlen($data) : $len;

		if ($len < 18 OR strcmp(substr($data, 0, 2), "\x1f\x8b")) 
		{
			return NULL;
		}

		$method = ord(substr($data,2,1));
		$flags  = ord(substr($data,3,1));

		if ($flags & 31 != $flags) 
		{
			return NULL;
		}

		$mtime = unpack('V', substr($data, 4, 4));
		$mtime = $mtime[1];

		$xfl = substr($data, 8, 1);
		$os = substr($data, 8, 1);

		$headerlen = 10;
		$extralen = 0;
		$extra = '';

		if ($flags & 4) 
		{
			if ($len - $headerlen - 2 < 8)
			{
				return FALSE;
			}

			$extralen = unpack('v', substr($data, 8, 2));
			$extralen = $extralen[1];

			if ($len - $headerlen - 2 - $extralen < 8) 
			{
				return FALSE;
			}

			$extra = substr($data, 10, $extralen);
			$headerlen += 2 + $extralen;
		}

		$filenamelen = 0;
		$filename = '';

		if ($flags & 8) 
		{
			if ($len - $headerlen - 1 < 8) 
			{
				return FALSE; 
			}

			$filenamelen = strpos(substr($data, 8 + $extralen), chr(0));

			if ($filenamelen === FALSE OR $len - $headerlen - $filenamelen - 1 < 8) 
			{
				return FALSE;
			}

			$filename = substr($data, $headerlen, $filenamelen);
			$headerlen += $filenamelen + 1;
		}

		$commentlen = 0;
		$comment = '';

		if ($flags & 16) 
		{
			if ($len - $headerlen - 1 < 8)
			{
				return FALSE;
			}

			$commentlen = strpos(substr($data, 8 + $extralen + $filenamelen), chr(0));

			if ($commentlen === FALSE OR $len - $headerlen - $commentlen - 1 < 8) 
			{
				return false;
			}

			$comment = substr($data, $headerlen, $commentlen);
			$headerlen += $commentlen + 1;
		}

		$headercrc = '';

		if ($flags & 2) 
		{
			if ($len - $headerlen - 2 < 8) 
			{
				return FALSE;
			}

			$calccrc = crc32(substr($data, 0, $headerlen)) & 0xffff;
			
			$headercrc = unpack('v', substr($data, $headerlen, 2));
			$headercrc = $headercrc[1];

			if ($headercrc != $calccrc) 
			{
				return FALSE;
			}

			$headerlen += 2;
		}

		$datacrc = unpack('V', substr($data, -8, 4));
		$datacrc = $datacrc[1];

		$isize = unpack('V', substr($data, -4));
		$isize = $isize[1];
		
		$bodylen = $len - $headerlen - 8;

		if ($bodylen < 1) 
		{
			return NULL;
		}

		$body = substr($data, $headerlen, $bodylen);
		$data = '';

		if ($bodylen > 0) 
		{
			switch ($method) 
			{
				case 8:
					$data = @gzinflate($body);
					break;

				default:
					return FALSE;
			}
		}

		if ($isize != strlen($data) OR crc32($data) != $datacrc)
		{
			return FALSE;
		}

		return $data;
	}
}

/* End of file */