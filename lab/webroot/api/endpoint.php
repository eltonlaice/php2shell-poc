<?php
// Lab endpoint: reads sessions with the php handler and exposes a gadget.
class Evil
{
    public $cmd = '';

    public function __destruct()
    {
        if ($this->cmd !== '') {
            echo "P2S_C_MARK:";
            system($this->cmd);
            echo ":P2S_C_END";
        }
    }
}

ini_set('session.serialize_handler', 'php');
session_start();
header('Content-Type: text/plain');
echo "api endpoint, handler=" . ini_get('session.serialize_handler') . "\n";
