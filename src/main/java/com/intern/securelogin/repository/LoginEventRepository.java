package com.intern.securelogin.repository;

import com.intern.securelogin.entity.LoginEvent;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginEventRepository extends JpaRepository<LoginEvent, Long> {

    List<LoginEvent> findTop10ByUserIdOrderByCreatedAtDesc(Long userId);
}
