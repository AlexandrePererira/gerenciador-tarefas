package br.com.treinaweb.twgerenciadortarefas.modelos;



import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import org.hibernate.validator.constraints.Length;
import org.springframework.format.annotation.DateTimeFormat;




@Entity
@Table(name = "tar_tarefas")
public class Tarefa {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "tar_id")
	private Long id;
	
	@Column(name = "tar_titulo", length = 50, nullable = false)
	@NotNull(message = "O título é obrigatório")
	@Length(max = 50, min = 3,  message = "O título dever ter no max 100 caracter e no minimo 3")
	private String titulo;
	
	@Column(name = "tar_descricao", length = 50, nullable = true)
	@Length(max = 100, message ="A descrição deve conter até 100 caracteres")
	private String descricao;
	
	
	@Column(name = "tar_data_expiracao", nullable = false)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date dataExpiracao;
	
	@Column(name = "tar_concluida", nullable = false)
	private Boolean concluida = false;

	public Tarefa() {
		
	}

	public Tarefa(Long id, String titulo, String descricao, Date dataExpiracao, Boolean concluida) {
		
		this.id = id;
		this.titulo = titulo;
		this.descricao = descricao;
		this.dataExpiracao = dataExpiracao;
		this.concluida = concluida;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getTitulo() {
		return titulo;
	}

	public void setTitulo(String titulo) {
		this.titulo = titulo;
	}

	public String getDescricao() {
		return descricao;
	}

	public void setDescricao(String descricao) {
		this.descricao = descricao;
	}

    
	
	public Date getDataExpiracao() {
		return dataExpiracao;
	}

	public void setDataExpiracao(Date dataExpiracao) {
		this.dataExpiracao = dataExpiracao;
	}

	public Boolean getConcluida() {
		return concluida;
	}

	public void setConcluida(Boolean concluida) {
		this.concluida = concluida;
	}

}
