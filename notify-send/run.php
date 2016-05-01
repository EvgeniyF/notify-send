#!/usr/bin/php
<?php

$email = 'email';
$password = 'password';
$managers = array
(
	$email,
);

include 'Socket.php';
include 'Http.php';

process($email, $password, $managers);

// --------------------------------------------------------------------------------------------------------------

function process($email, $password, $managers)
{
	if ($cookie = login($email, $password))
	{
		while(TRUE)
		{
			run($cookie, $managers);
			sleep(10);
		}

		process($email, $password, $managers);
	}
}

function login($email, $password)
{
	$http = new Http;
	$body = 'Email='.urlencode($email).'&Password='.urlencode($password).'&IsRemember=1&ReOpen=yes&XMLHttpRequest=yes';
	$cookie = array('Email' => urlencode($email));

	if (!$socket = $http->open('manager.host-food.ru', 443, TRUE, 10, STREAM_CRYPTO_METHOD_SSLv3_CLIENT))
	{
		echo __FUNCTION__.": Ошибка соединения с сервером.\n";
		return FALSE;
	}

	$request = $http->generate_request('POST', '/API/Logon', array
	(
		'Host' => 'manager.host-food.ru',
		'Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8',
		'Content-Length' => strlen($body),
		'Connection' => 'close'
	), $body);

	if (!$http->write($socket, $request))
	{
		echo __FUNCTION__.": Ошибка записи в сокет.\n";
		$http->close($socket);
		return FALSE;
	}

	$content = $http->get_content($socket);
	$http->close($socket);

	if ($http->validate_content($content, 200) !== TRUE)
	{
		echo __FUNCTION__.": Ошибка при чтения из сокета.\n";
		return FALSE;
	}

	$data = json_decode($content['body'], TRUE);

	if (isset($data['Status']) AND $data['Status'] == 'Ok')
	{
		return 'Email='.urlencode($email).'; SessionID='.$data['SessionID']; // p=9374;
	}
	else
	{
		echo __FUNCTION__.": Ошибка авторизации. Не верный логин или пароль.\n";
	}

	return FALSE;
}

function run($cookie, $managers)
{
	$http = new Http;

	if (!$socket = $http->open('manager.host-food.ru', 443, TRUE, 10, STREAM_CRYPTO_METHOD_SSLv3_CLIENT))
	{
		echo __FUNCTION__.": Ошибка соединения с сервером.\n";
		return;
	}

	$request = $http->generate_request('GET', '/API/Events', array
	(
		'Host' => 'manager.host-food.ru',
		'Connection' => 'close',
		'Cookie' => $cookie,	
	));
	
	if (!$http->write($socket, $request))
	{
		echo __FUNCTION__.": Ошибка записи в сокет.\n";
		$http->close($socket);
		return;
	}

	$content = $http->get_content($socket);
	$http->close($socket);

	if ($http->validate_content($content, 200) !== TRUE)
	{
		echo __FUNCTION__.": Ошибка при чтения из сокета.\n";;
		return;
	}

	$data = json_decode($content['body'], TRUE);

	if (isset($data['Status']) AND $data['Status'] == 'Ok')
	{
		foreach ($data['Events'] as $event)
		{
			print $event['UserInfo']."\n";
			print $event['Text']."\n\n\n";

			if ($event['PriorityID'] == 'Billing')
			{
				foreach ($managers as $manager)
				{
					if (strpos($event['UserInfo'], '['.$manager.']') !== FALSE)
					{
						continue 2;
					}
				}

				if (strpos($event['Text'], 'Добавлено новое сообщение к запросу') !== FALSE /*OR
				    strpos($event['Text'], 'Создан новый запрос в службу поддержки') !== FALSE*/)
				{

					system('notify-send -t 1000 -i /usr/share/icons/hicolor/48x48/apps/evolution-mail.png "'.$event['UserInfo'].'" "'.$event['Text'].'"');
					#system('mpg321 ~/notify/rad.mp3 > /dev/null 2>/dev/null');
					#system('eject -T');
					system('beep -f 550 -l 150 -r3'); //sudo modprobe pcspkr
				}

				if (strpos($event['Text'], 'Создан новый запрос в службу поддержки') !== FALSE)
				{
					system('notify-send -t 1000 -i /usr/share/icons/hicolor/48x48/apps/evolution-mail.png "'.$event['UserInfo'].'" "'.$event['Text'].'"');
					system('beep -f 940 -l 150 -r3');	
				}
			}
		}	
	}
}
